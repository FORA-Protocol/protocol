# Python SDK changelog

The changes to the public API of the Python SDK (the `fora_sdk` package,
published as `fora-protocol-sdk`), by release. The protocol's own changes are in
[`proto/CHANGELOG.md`](../../proto/CHANGELOG.md).

The Python SDK's API gate (`scripts/gates/gate-api-python.sh`) reads this file.
Within a major version the public API only grows: a removed, renamed or changed
public object or parameter fails the gate. To rename a function, keep the old name
as a deprecated alias that calls the new one, warns with
`warnings.warn(..., DeprecationWarning, stacklevel=2)` and says so in its
docstring, and remove it in the next major version. A major release may remove or
change a symbol: list it under a `### Breaking` heading in the first section
below, which is headed `Unreleased` or with the release's version, spelled in
backticks as the gate prints it, for example `` `fora_sdk.money.parse_money` ``.
[ADR-004](../../docs/architecture/adr-004-sdk-api-gates.md) records the rule.

## Unreleased
