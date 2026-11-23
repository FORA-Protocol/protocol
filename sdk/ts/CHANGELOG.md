# TypeScript SDK changelog

The changes to the public API of the TypeScript SDK (the entry points of
`sdk/ts/package.json`, published as `@fora-protocol/sdk`), by release. The
protocol's own changes are in [`proto/CHANGELOG.md`](../../proto/CHANGELOG.md).

The TypeScript SDK's API gate (`scripts/gates/gate-api-ts.sh`) reads this file.
Within a major version the public API only grows: a removed, renamed or changed
export or member fails the gate. To rename a function, keep the old name as a
deprecated alias that calls the new one, with an `@deprecated` tag in its JSDoc,
and remove it in the next major version. A major release may remove or change a
symbol: list it under a `### Breaking` heading in the first section below, which is
headed `Unreleased` or with the release's version, spelled in backticks as the gate
prints it: the entry point's export subpath and the symbol's path, for example
`` `./core.Verifier.sort` ``. The API report of each entry point is committed under
`sdk/ts/api`; `python3 scripts/gates/api_diff.py ts --update` rewrites them after a
change to the API.
[ADR-004](../../docs/architecture/adr-004-sdk-api-gates.md) records the rule.

## Unreleased
