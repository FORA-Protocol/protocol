# Architecture decisions

Each file records one decision about how this repository is built and checked:
the context, the decision, and what enforces it. Decisions about the wire format
itself are in [`../design-history.md`](../design-history.md).

| Decision | Subject |
|---|---|
| [ADR-001](adr-001-agent-instructions-and-quality-gates.md) | Written instructions for contributors and agents, and shrink-only quality gates |
| [ADR-002](adr-002-conformance-corpora.md) | The conformance-corpus contract |
| [ADR-003](adr-003-sdk-test-suites.md) | How the SDK test suites are written |
| [ADR-004](adr-004-sdk-api-gates.md) | The SDKs' public API is gated against breaking changes |
