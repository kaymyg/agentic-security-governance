# Home Lab: Agent Security on a Laptop

A guide to running the real versions of this repo's building blocks on one machine: a local Kubernetes cluster, SPIRE for workload identity, OPA behind Envoy for policy enforcement, and Cilium Tetragon for kernel-level visibility.

> ⚠️ **Untested in this repo.** These commands follow the upstream projects' published install paths, but chart names, values and versions change. Check each project's docs before running anything, and pin versions once something works for you. Corrections are very welcome (see the repo issues).

---

## What you need

* A Linux machine, or macOS/Windows with a Linux VM. Tetragon needs a Linux kernel with BTF support (most recent distributions have it; check upstream docs for the minimum version).
* 8 GB RAM or more, 4 CPU cores recommended.
* Installed tools: `docker` (or another container runtime), `kubectl`, `helm`, and either `kind` or `k3s`.

---

## 1. Create a cluster

**Option A, kind (runs Kubernetes inside Docker):**

```bash
kind create cluster --name agent-lab
kubectl cluster-info --context kind-agent-lab
```

**Option B, k3s (lightweight Kubernetes on the host, Linux only):**

```bash
curl -sfL https://get.k3s.io | sh -
sudo k3s kubectl get nodes
# optional: export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

Note: Tetragon inside kind sees the kind node container's kernel, which is your host kernel. It generally works, but check the Tetragon docs for kind-specific notes.

---

## 2. SPIRE (workload identity)

SPIRE issues short-lived identities (SVIDs) to workloads after attesting what they are. The SPIFFE project publishes Helm charts at `spiffe/helm-charts` (also called helm-charts-hardened).

```bash
helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/
helm repo update

# CRDs first, then SPIRE itself (chart names: check upstream README)
helm upgrade --install --create-namespace -n spire-mgmt spire-crds spiffe/spire-crds
helm upgrade --install -n spire-mgmt spire spiffe/spire \
  --set global.spire.trustDomain=agent-lab.local
```

Check it is running:

```bash
kubectl get pods -A | grep spire
```

**Try:** deploy a pod labelled as an agent and fetch its SVID through the SPIFFE Workload API (the SPIRE docs have a quickstart that does this with `spire-agent api fetch`). That identity is what `agentguard/pep.py` would accept in place of its HMAC tokens; see the Phase 1 help-wanted items in [../docs/roadmap.md](../docs/roadmap.md).

---

## 3. OPA behind Envoy (policy enforcement point)

The pattern: an Envoy sidecar sits next to the agent, and for every outbound request it asks OPA (via Envoy's `ext_authz` filter) whether to allow it. OPA evaluates `policies/agent_tools.rego`.

The OPA project publishes an Envoy plugin image, `openpolicyagent/opa:latest-envoy`, and a tutorial with complete manifests. Follow it rather than copying fragments:

* OPA Envoy tutorial: https://www.openpolicyagent.org/docs/latest/envoy-tutorial-standalone-envoy/

Then swap in this repo's policy. You can test the policy locally first, without a cluster:

```bash
opa test policies/ -v
```

The input shape Envoy sends differs from the shape `agent_tools.rego` expects. Adapting it (a small wrapper rule that reads the HTTP path and headers) is an open task.

---

## 4. Tetragon (kernel-level visibility)

Tetragon uses eBPF to observe process, file and network activity from the kernel, so a compromised agent cannot simply edit its own logs to hide.

```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon -w
```

### Example policy: outbound connections from agents

`tetragon-agent-egress.yaml` in this folder hooks the kernel's `tcp_connect` for pods labelled `app.kubernetes.io/component=agent`:

```bash
kubectl apply -f lab/tetragon-agent-egress.yaml
```

### Example policy: a process opening /etc/shadow

A starting point (untested; check the file-monitoring examples in the Tetragon docs for the current field names):

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: watch-shadow
spec:
  kprobes:
    - call: "security_file_permission"
      syscall: false
      args:
        - index: 0
          type: "file"
        - index: 1
          type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "/etc/shadow"
```

### Watch events

```bash
kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```

Then run something in an agent-labelled pod (for example `curl https://example.com`, or `cat /etc/shadow`) and watch the events appear.

---

## 5. Connect it back to the repo

| Lab component | Repo stand-in | Next step |
| --- | --- | --- |
| SPIRE SVIDs | `agentguard/capability.py` | Accept JWT-SVIDs in the PEP |
| Envoy + OPA | `agentguard/pep.py`, `policies/agent_tools.rego` | Adapt the policy to Envoy's input |
| Tetragon | `agentguard/audit.py` | Feed kernel events into the audit trail |

---

## Teardown

```bash
# remove policies and Tetragon
kubectl delete -f lab/tetragon-agent-egress.yaml --ignore-not-found
helm uninstall tetragon -n kube-system

# remove SPIRE
helm uninstall spire -n spire-mgmt
helm uninstall spire-crds -n spire-mgmt

# delete the whole cluster
kind delete cluster --name agent-lab          # if you used kind
/usr/local/bin/k3s-uninstall.sh               # if you used k3s
```
