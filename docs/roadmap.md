# Roadmap

A phased plan for turning [architecture.md](architecture.md) into something real. Phases are ordered by value per unit of effort: each one makes the next one safer and cheaper.

Legend: `[x]` done in this repo, `[ ]` open. 🙋 **Help wanted** marks items where contributions are especially welcome.

---

## Phase 0: Foundational hygiene

**Goal:** close the boring gaps that most real breaches still go through.

- [ ] Guide: phishing-resistant MFA (FIDO2/WebAuthn) for every human with access to agent infrastructure
- [ ] Guide: automated dependency and base image patching (for example Dependabot or Renovate)
- [ ] Guide: network minimization, default-deny egress for agent workloads
- [x] CI that runs the test suite on every push

---

## Phase 1: Identity & authority

**Goal:** every agent has a verifiable identity and only the authority its current task needs, for minutes, not months.

- [x] Task-bound capability tokens with 60 to 900 second TTLs (`agentguard/capability.py`)
- [x] Revocation and kill-switch bus, in-process (`agentguard/revocation.py`)
- [x] Policy enforcement point for tool calls (`agentguard/pep.py`)
- [x] OPA policy for tool allowlisting (`policies/agent_tools.rego`)
- [ ] 🙋 **Help wanted:** SPIRE integration, issue JWT-SVIDs and accept them in the PEP instead of HMAC tokens
- [ ] 🙋 **Help wanted:** Envoy ext_authz sidecar calling the OPA policy, with a working example in `lab/`
- [ ] 🙋 **Help wanted:** Redis or Kafka backend for the revocation bus
- [x] Provenance check, fail closed: only `user` and `system` instructions may trigger side effects (`agentguard/pep.py`, `policies/agent_tools.rego`)
- [ ] 🙋 **Help wanted:** signed provenance tags set by the orchestrator and verified by the sidecar, so a compromised runtime cannot lie about where an instruction came from
- [ ] MCP server allowlist with version pinning

---

## Phase 2: Circuit breakers, honey-tokens and audit

**Goal:** hard limits that hold no matter what the model outputs, plus tripwires and a tamper-evident record.

- [x] Per-action caps and rolling-window budgets (`agentguard/breakers.py`)
- [x] Honey-token planting and outbound scanning (`agentguard/honeytokens.py`)
- [x] Hash-chained, tamper-evident audit log (`agentguard/audit.py`)
- [x] End-to-end demo of a prompt-injected agent being contained (`python -m agentguard.demo`)
- [x] Human approval required for irreversible tools (`agentguard/pep.py`, risk-tier aware in `policies/agent_tools.rego`)
- [ ] 🙋 **Help wanted:** ship audit records to off-host append-only storage (for example a transparency log or WORM bucket)

---

## Phase 3: Behavioral detection

**Goal:** see what agents actually do at the kernel and tool-call level, and spot abnormal patterns fast.

- [ ] 🙋 **Help wanted:** Tetragon TracingPolicies for agent workloads, tested on kind/k3s (starting point: `lab/tetragon-agent-egress.yaml`)
- [ ] Tool-call tracing via OpenTelemetry, metadata first, content optional
- [ ] 🙋 **Help wanted:** velocity and fan-out analytics over tool-call events (a simple streaming baseline before any graph database)
- [ ] Token and compute burn anomaly detection per agent identity
- [ ] Tiered containment playbooks (automatic for reversible actions, human approval for data rollback)

---

## Phase 4: Continuous adversarial validation

**Goal:** find weaknesses in your own agent stack before someone else does.

- [ ] 🙋 **Help wanted:** prompt-injection test corpus run against the PEP in CI
- [ ] Red-team scenarios for RAG poisoning and MCP tool description injection
- [ ] Patch-diff watcher for dependencies, flagging security-relevant changes
- [ ] Virtual patching via generated OPA rules, with human review

---

## Phase 5: Deception and moving target defense

**Goal:** make automated attackers waste time and reveal themselves.

Caveats: MTD breaks your own clients and monitoring first, and honey-tokens are very high-confidence but not zero false positive. See [critique-and-gaps.md](critique-and-gaps.md).

- [ ] Decoy microservice that alerts on any request
- [ ] Honey-records planted in a sample RAG store
- [ ] MTD experiment limited to decoy surfaces, with a breakage measurement
- [ ] MicroVM or gVisor sandbox for running agent-generated code
