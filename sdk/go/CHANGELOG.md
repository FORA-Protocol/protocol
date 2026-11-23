# Go SDK changelog

The changes to the public API of the Go SDK (the packages under `sdk/go`), by
release. The protocol's own changes are in
[`proto/CHANGELOG.md`](../../proto/CHANGELOG.md).

The Go SDK's API gate (`scripts/gates/gate-api-go.sh`) reads this file. Within a
major version the public API only grows: a removed, renamed or changed exported
symbol fails the gate. To rename a symbol, keep the old name as a deprecated alias
that calls the new one (`// Deprecated: use NewName.`), and remove it in the next
major version. A major release may remove or change a symbol: list it under a
`### Breaking` heading in the first section below, which is headed `Unreleased` or
with the release's version, spelled in backticks as the gate prints it, for example
`` `./sdk/go/core.Verifier` ``.
[ADR-004](../../docs/architecture/adr-004-sdk-api-gates.md) records the rule.

## Unreleased
