# Critique and Gaps

An honest review of [architecture.md](architecture.md): what holds up, where it overpromises, and what is missing. Each item comes with a concrete mitigation, so this doubles as a design checklist.

---

## What is strong

### 1. Layer 1 is the most mature part

SPIFFE/SPIRE workload identity, short-lived scoped tokens and an Envoy plus OPA/Cedar policy proxy are real, production-grade patterns you can run today, even on a laptop.

**Make it count:** start here. Short TTLs and per-task scopes shrink the blast radius of every other failure, including the ones the rest of the architecture fails to detect.

### 2. Deterministic circuit breakers may be the most important idea in the document

Hard caps on rows deleted, funds moved or payload size apply no matter what the model says. A prompt injection cannot talk its way past a number in code.

**Make it count:** put breakers in the execution path, not in the agent. Count usage per identity over rolling windows (not just per call), so slow, chained micro-actions still hit a budget. See `agentguard/breakers.py`.

### 3. eBPF kernel sensing is a smart choice

A compromised agent can rewrite its own logs, but it cannot easily hide its syscalls and network connections from kernel-level sensors.

**Make it count:** treat kernel telemetry as the ground truth and application logs as claims to be cross-checked against it.

---

## Where it overpromises

### 1. "Intent-to-action alignment" is an unsolved problem, not a component

Checking whether a tool call matches the user's original intent mostly means asking another model to judge, and that judge can be fooled by the same injection.

**Mitigation:**
* Per-task-type tool allowlists ("a summarization task may call `read_doc` and nothing else").
* Provenance tagging: mark which instructions came from the user and which came from untrusted content (web pages, emails, RAG chunks). Untrusted text should never be able to widen permissions.
* Human approval for anything irreversible. Use model-based intent checks only as an extra signal, never as the only gate.

### 2. "Zero-false-positive" honey-tokens is too strong

False positives are rare but real. Your own secret scanners, backup jobs, search indexers or a curious engineer can trip a canary.

**Mitigation:** treat a hit as very high-confidence, not certain. Auto-revoke the token the agent holds (cheap and reversible), but attach context (who, what, where planted) for a human before anything destructive happens. Exclude known scanners by identity, not by hiding the canary.

### 3. Sub-second automated containment can become self-inflicted downtime

If an anomaly score can trigger revocation, quarantine and database rollback, a false positive takes production down.

**Mitigation:** tier the playbook by reversibility.

| Action | Reversible? | Automation |
| --- | --- | --- |
| Revoke a token | Yes | Fully automatic |
| Quarantine a pod | Mostly | Automatic, with alert |
| Snapshot memory/state | Yes | Automatic |
| Roll back data | No (often) | Human approval |

### 4. Moving target defense breaks your own systems first

Rotating internal endpoints and parameter names confuses your clients, monitoring, runbooks and on-call engineers long before it confuses an attacker.

**Mitigation:** apply MTD only behind a stable internal contract (service mesh names that resolve to rotating backends), or limit it to decoy surfaces. Measure your own breakage before rolling it out.

### 5. Tracing "model reasoning chains" creates a new sensitive data store

These logs will hold prompts, customer data and sometimes secrets pasted into prompts.

**Mitigation:** log decisions and metadata by default (tool name, identity, allow/deny, reason, sizes), not raw content. If you must keep content, encrypt it, restrict access, and set short retention. `agentguard/audit.py` follows the metadata-first approach.

---

## What is missing

### 1. Data classification

Policies cannot protect "sensitive data" if nothing says which data is sensitive.

**Mitigation:** label data stores and fields (public, internal, confidential, restricted) and put the label into token claims and policy inputs.

### 2. Human approval tiers for irreversible actions

Sending money, deleting records and emailing people outside the organization should not depend on anomaly detection catching a mistake after the fact.

**Mitigation:** define a short list of irreversible action types that always require a human click, enforced at the PEP.

### 3. MCP server allowlisting and version pinning

The blueprint red-teams MCP tool servers but never controls which ones agents may connect to.

**Mitigation:** maintain an allowlist of approved MCP servers with pinned versions and verified signatures. Deny unknown servers at the PEP. Review tool descriptions on every update, since a changed description is itself an injection vector.

### 4. A phased rollout

Almost no team can build all four layers at once, and half-built layers give false confidence.

**Mitigation:** follow [roadmap.md](roadmap.md): hygiene first, then identity and authority, then circuit breakers, then detection, then the rest.

### 5. Cost and operability

Streaming graph analytics, digital twins and red-team swarms are expensive to run and to staff.

**Mitigation:** for each component, write down what it costs, who owns it and what simpler control it replaces. Prefer boring, deterministic controls where they are good enough.
