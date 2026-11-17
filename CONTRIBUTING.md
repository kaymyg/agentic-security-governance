# Contributing

Thanks for helping. This is a learning-oriented project, so clear, readable code beats clever code.

## Ways to help

* Pick an issue labelled `help wanted` or `good first issue`.
* Try the [lab guide](lab/README.md) on your own machine and report what broke.
* Challenge the design. If you think a control in [docs/architecture.md](docs/architecture.md) is wrong or oversold, open a discussion issue and say why.

## Ground rules

* **No offensive tooling.** This repo is defensive. Do not submit working exploits, malware or attack automation aimed at real systems. Red-team work belongs in sandboxed simulations against this repo's own components.
* **Keep the core dependency-free.** `agentguard/` uses only the Python standard library so anyone can read and run it. Integrations (SPIRE, Envoy, Tetragon) go in separate folders.
* **Every control needs a test,** including at least one test showing it blocks the thing it is meant to block.
* **Be honest in docs.** Mark untested commands as untested, and do not claim guarantees (like "zero false positives") the code cannot back up.

## Development

```bash
pip install -e ".[dev]"
pytest -v
python -m agentguard.demo
opa test policies/ -v   # needs OPA installed
```

## Reporting a security problem

If you find a way to bypass one of the controls, please open an issue with the label `bypass`. This is a reference implementation, not production software, so public discussion is fine and helps everyone learn.
