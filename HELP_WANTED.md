# Help wanted

Agentic Security Governance is open to contributions. Below is the hardening work that would make it stronger, roughly in order of impact. Pick anything, comment on (or open) an issue so others know you are on it, and see [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

Found a vulnerability instead? Please report it privately, see [SECURITY.md](SECURITY.md).


### Fuzz the policy enforcement point

**High impact.** Generate malformed and adversarial tool calls and check the enforcement point always fails closed.

### More indirect prompt injection cases

**Medium.** Add test cases from public injection datasets to the provenance checks, including ones that should NOT be blocked.

### Policy unit tests

**Medium.** Each policy under `policies/` should have tests for both allow and deny paths.
