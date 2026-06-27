#!/usr/bin/env python3
# Copyright 2026 nezdali
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
"""Aggregate Kubernetes RBAC permissions per Pod.

For every Pod in the cluster (or a chosen namespace), figure out which
ServiceAccount it runs as and which (Cluster)Role rules that account ends
up with through (Cluster)RoleBindings. Print the result as text or JSON.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from kubernetes import client, config
from kubernetes.client.rest import ApiException

log = logging.getLogger("rbac-aggregator")

# (namespace, name) for ServiceAccount; namespace is "" for cluster-scoped subjects.
SaKey = tuple[str, str]
# (kind, namespace, name) for a Role or ClusterRole. namespace is "" for ClusterRole.
RoleKey = tuple[str, str, str]


@dataclass(frozen=True)
class Rule:
    """A single RBAC PolicyRule, flattened for printing."""

    api_groups: tuple[str, ...]
    resources: tuple[str, ...]
    verbs: tuple[str, ...]
    resource_names: tuple[str, ...] = ()
    non_resource_urls: tuple[str, ...] = ()

    @classmethod
    def from_api(cls, rule: client.V1PolicyRule) -> Rule:
        return cls(
            api_groups=tuple(rule.api_groups or ()),
            resources=tuple(rule.resources or ()),
            verbs=tuple(rule.verbs or ()),
            resource_names=tuple(rule.resource_names or ()),
            non_resource_urls=tuple(rule.non_resource_urls or ()),
        )


@dataclass
class PodInfo:
    namespace: str
    name: str
    service_account: str  # name only; namespace is the pod's namespace


@dataclass
class PodAccess:
    pod: PodInfo
    # role_kind -> role_key -> rules
    rules_by_role: dict[RoleKey, list[Rule]] = field(default_factory=dict)


def _load_kube_config(kubeconfig: str | None, context: str | None, in_cluster: bool) -> None:
    if in_cluster:
        config.load_incluster_config()
        log.debug("Loaded in-cluster config")
        return
    try:
        config.load_kube_config(config_file=kubeconfig, context=context)
        log.debug("Loaded kubeconfig%s%s",
                 f" from {kubeconfig}" if kubeconfig else "",
                 f" (context={context})" if context else "")
    except config.ConfigException:
        # Fall back to in-cluster if no kubeconfig is available.
        config.load_incluster_config()
        log.debug("Falling back to in-cluster config")


class RbacAggregator:
    """Pulls all the RBAC objects once, then answers per-pod queries in memory."""

    def __init__(self, namespace: str | None = None) -> None:
        self._core = client.CoreV1Api()
        self._rbac = client.RbacAuthorizationV1Api()
        self._namespace = namespace

    # ---------- fetchers ----------

    def _list_pods(self) -> list[client.V1Pod]:
        if self._namespace:
            return self._core.list_namespaced_pod(self._namespace, watch=False).items
        return self._core.list_pod_for_all_namespaces(watch=False).items

    def _list_roles(self) -> list[client.V1Role]:
        return self._rbac.list_role_for_all_namespaces(watch=False).items

    def _list_role_bindings(self) -> list[client.V1RoleBinding]:
        return self._rbac.list_role_binding_for_all_namespaces(watch=False).items

    def _list_cluster_roles(self) -> list[client.V1ClusterRole]:
        return self._rbac.list_cluster_role(watch=False).items

    def _list_cluster_role_bindings(self) -> list[client.V1ClusterRoleBinding]:
        return self._rbac.list_cluster_role_binding(watch=False).items

    # ---------- core algorithm ----------

    def aggregate(self) -> list[PodAccess]:
        pods = [
            PodInfo(
                namespace=p.metadata.namespace,
                name=p.metadata.name,
                # pre-1.25 sometimes used `service_account`; both are mirrors of the same field.
                service_account=p.spec.service_account_name or "default",
            )
            for p in self._list_pods()
        ]
        log.info("Fetched %d pods", len(pods))

        # role/clusterrole rules indexed by (kind, namespace, name)
        rules_by_role: dict[RoleKey, list[Rule]] = {}
        for r in self._list_roles():
            key: RoleKey = ("Role", r.metadata.namespace, r.metadata.name)
            rules_by_role[key] = [Rule.from_api(x) for x in (r.rules or [])]
        for r in self._list_cluster_roles():
            key = ("ClusterRole", "", r.metadata.name)
            rules_by_role[key] = [Rule.from_api(x) for x in (r.rules or [])]
        log.info("Fetched %d Roles, %d ClusterRoles",
                 sum(1 for (k, _, _) in rules_by_role if k == "Role"),
                 sum(1 for (k, _, _) in rules_by_role if k == "ClusterRole"))

        # ServiceAccount -> list of role keys it has been bound to
        sa_to_roles: dict[SaKey, set[RoleKey]] = defaultdict(set)

        for rb in self._list_role_bindings():
            self._index_binding(
                binding_namespace=rb.metadata.namespace,
                role_ref=rb.role_ref,
                subjects=rb.subjects or [],
                target=sa_to_roles,
            )
        for crb in self._list_cluster_role_bindings():
            self._index_binding(
                binding_namespace="",  # cluster-scoped
                role_ref=crb.role_ref,
                subjects=crb.subjects or [],
                target=sa_to_roles,
            )
        log.info("Indexed bindings for %d distinct service accounts", len(sa_to_roles))

        # join pods <- service accounts -> roles -> rules
        results: list[PodAccess] = []
        for pod in pods:
            sa_key: SaKey = (pod.namespace, pod.service_account)
            role_keys = sa_to_roles.get(sa_key, set())
            if not role_keys:
                continue
            access = PodAccess(pod=pod)
            for rk in sorted(role_keys):
                rules = rules_by_role.get(rk)
                if rules:
                    access.rules_by_role[rk] = rules
            if access.rules_by_role:
                results.append(access)
        return results

    @staticmethod
    def _index_binding(
        binding_namespace: str,
        role_ref: client.V1RoleRef,
        subjects: Iterable[client.RbacV1Subject],
        target: dict[SaKey, set[RoleKey]],
    ) -> None:
        # role_ref.kind is "Role" or "ClusterRole".
        # For a RoleBinding, a "Role" ref is in the binding's namespace; "ClusterRole" is cluster-scoped.
        if role_ref.kind == "Role":
            role_key: RoleKey = ("Role", binding_namespace, role_ref.name)
        else:
            role_key = ("ClusterRole", "", role_ref.name)

        for s in subjects:
            if s.kind != "ServiceAccount":
                continue
            # Subject namespace is required for SAs in ClusterRoleBindings; for RoleBindings it
            # defaults to the binding's namespace if omitted.
            sa_ns = s.namespace or binding_namespace
            target[(sa_ns, s.name)].add(role_key)


# ---------------- output ----------------

def render_text(results: list[PodAccess]) -> str:
    lines: list[str] = []
    for access in results:
        p = access.pod
        lines.append(f"Pod: {p.namespace}/{p.name}  (sa={p.service_account})")
        for (kind, ns, name), rules in access.rules_by_role.items():
            scope = f"{ns}/" if ns else ""
            lines.append(f"  {kind}: {scope}{name}")
            for r in rules:
                ag = ",".join(r.api_groups) or "*"
                res = ",".join(r.resources) or "-"
                verbs = ",".join(r.verbs) or "-"
                extras = []
                if r.resource_names:
                    extras.append(f"names={','.join(r.resource_names)}")
                if r.non_resource_urls:
                    extras.append(f"urls={','.join(r.non_resource_urls)}")
                tail = f"  [{'; '.join(extras)}]" if extras else ""
                lines.append(f"    apiGroups={ag}  resources={res}  verbs={verbs}{tail}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(results: list[PodAccess]) -> str:
    payload = [
        {
            "pod": {
                "namespace": a.pod.namespace,
                "name": a.pod.name,
                "serviceAccount": a.pod.service_account,
            },
            "roles": [
                {
                    "kind": kind,
                    "namespace": ns or None,
                    "name": name,
                    "rules": [
                        {
                            "apiGroups": list(r.api_groups),
                            "resources": list(r.resources),
                            "verbs": list(r.verbs),
                            "resourceNames": list(r.resource_names) or None,
                            "nonResourceURLs": list(r.non_resource_urls) or None,
                        }
                        for r in rules
                    ],
                }
                for (kind, ns, name), rules in a.rules_by_role.items()
            ],
        }
        for a in results
    ]
    return json.dumps(payload, indent=2, sort_keys=False)


# ---------------- CLI ----------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="sa-rbac-aggregator",
        description="Aggregate Kubernetes RBAC permissions per Pod, "
                    "via the ServiceAccount each Pod runs under.",
    )
    p.add_argument("-n", "--namespace", help="Limit to a single namespace (default: all).")
    p.add_argument("--kubeconfig", help="Path to kubeconfig (default: $KUBECONFIG or ~/.kube/config).")
    p.add_argument("--context", help="kubeconfig context to use.")
    p.add_argument("--in-cluster", action="store_true",
                   help="Use in-cluster service-account credentials.")
    p.add_argument("-o", "--output", choices=("text", "json"), default="text",
                   help="Output format (default: text).")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="-v for INFO, -vv for DEBUG.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    level = logging.WARNING - 10 * args.verbose
    logging.basicConfig(level=max(level, logging.DEBUG),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    try:
        _load_kube_config(args.kubeconfig, args.context, args.in_cluster)
    except (config.ConfigException, FileNotFoundError) as e:
        log.error("Could not load Kubernetes config: %s", e)
        return 2

    aggregator = RbacAggregator(namespace=args.namespace)
    try:
        results = aggregator.aggregate()
    except ApiException as e:
        log.error("Kubernetes API error: %s", e)
        return 1

    out = render_json(results) if args.output == "json" else render_text(results)
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
