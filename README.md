# k8s-rbac-aggregator

Answers the question: **"What can each Pod actually do in this cluster?"**

The script walks the Kubernetes API and joins:

- Every `Pod` &rarr; its `ServiceAccount`
- Every `(Cluster)RoleBinding` &rarr; the `(Cluster)Role` it references and the
  subjects it binds
- Every `(Cluster)Role` &rarr; its rules

…and prints one consolidated view per Pod showing exactly which API resources
and verbs that pod's identity is allowed to invoke.

Useful for security audits, least-privilege reviews, and figuring out why a
workload "magically" has access to something.

---

## Install

Requires **Python 3.10+** and access to a Kubernetes cluster (kubeconfig or
in-cluster credentials).

```bash
# from PyPI-style local install (recommended)
pipx install git+https://github.com/nezdali/k8s-rbac-aggregator.git

# or in a venv
python -m venv .venv
. .venv/bin/activate           # PowerShell: .venv\Scripts\Activate.ps1
pip install git+https://github.com/nezdali/k8s-rbac-aggregator.git

# or just run the script directly
pip install "kubernetes>=30"
python sa_rbac_aggregator.py
```

After install you get a `sa-rbac-aggregator` console command.

## Usage

```text
usage: sa-rbac-aggregator [-h] [-n NAMESPACE] [--kubeconfig KUBECONFIG]
                          [--context CONTEXT] [--in-cluster]
                          [-o {text,json}] [-v]

options:
  -n, --namespace          Limit to a single namespace (default: all).
  --kubeconfig PATH        Path to kubeconfig (default: $KUBECONFIG or
                           ~/.kube/config).
  --context NAME           kubeconfig context to use.
  --in-cluster             Use in-cluster service-account credentials.
  -o, --output {text,json} Output format (default: text).
  -v                       Verbose; -vv for debug.
```

### Examples

Audit the whole cluster, human-readable:

```bash
sa-rbac-aggregator
```

Just the `kube-system` namespace, JSON:

```bash
sa-rbac-aggregator -n kube-system -o json | jq '.[] | .pod.name'
```

Pick a non-default kubeconfig context:

```bash
sa-rbac-aggregator --context staging
```

Run from inside a cluster:

```bash
sa-rbac-aggregator --in-cluster
```

## Example output (text)

```
Pod: kube-system/coredns-5b8b9b6c4f-x9z7p  (sa=coredns)
  ClusterRole: system:coredns
    apiGroups=*       resources=endpoints,services,pods,namespaces  verbs=list,watch
    apiGroups=*       resources=nodes                                verbs=get

Pod: kube-system/metrics-server-7d4f7d4f4f-abcde  (sa=metrics-server)
  ClusterRole: system:metrics-server
    apiGroups=*       resources=pods,nodes,nodes/stats               verbs=get,list,watch
  ClusterRole: system:auth-delegator
    apiGroups=authentication.k8s.io  resources=tokenreviews          verbs=create
```

Pods whose ServiceAccount has no bindings are omitted from the output.

## In-cluster usage

When running inside a pod, give that pod the read-only RBAC needed to inspect
the API:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rbac-aggregator
  namespace: rbac-audit
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: rbac-aggregator
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: rbac-aggregator
subjects:
- kind: ServiceAccount
  name: rbac-aggregator
  namespace: rbac-audit
roleRef:
  kind: ClusterRole
  name: rbac-aggregator
  apiGroup: rbac.authorization.k8s.io
```

Then in your Pod's spec:

```yaml
serviceAccountName: rbac-aggregator
containers:
- name: aggregator
  image: python:3.13-slim
  command: ["sh", "-c"]
  args:
    - |
      pip install --quiet git+https://github.com/nezdali/k8s-rbac-aggregator.git &&
      sa-rbac-aggregator --in-cluster -o json
```

## How matching works (and what it ignores)

- A Pod's identity is `(pod.namespace, pod.spec.serviceAccountName)`. If
  `serviceAccountName` is unset it defaults to `"default"`.
- Each `RoleBinding` or `ClusterRoleBinding` adds entries to a map keyed by
  ServiceAccount &rarr; set of `(Role|ClusterRole, namespace, name)`.
  - For a `RoleBinding` that references a `Role`, the role lives in the
    binding's namespace.
  - For a `RoleBinding` that references a `ClusterRole`, the rules apply only
    in the binding's namespace (this tool reports the full rule set — be
    aware that the actual access is namespace-scoped).
  - For a `ClusterRoleBinding`, the rules apply cluster-wide.
- `User` and `Group` subjects are ignored — this tool is about Pods, which
  always authenticate as ServiceAccounts.

## Development

```bash
git clone https://github.com/nezdali/k8s-rbac-aggregator.git
cd k8s-rbac-aggregator
python -m venv .venv
. .venv/bin/activate
pip install -e .
pip install ruff
ruff check .
```

## License

Apache License, Version 2.0. See [`LICENSE`](LICENSE).
