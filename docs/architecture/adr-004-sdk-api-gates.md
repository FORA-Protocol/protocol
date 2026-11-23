# ADR-004: The SDKs' public API is gated against breaking changes

Status: Accepted. The API gates enforce it: `scripts/gates/gate-api-go.sh` for
the Go SDK.

## Context

`buf breaking` holds the wire format to additive changes within `fora.v1`, and
fails against the v1.0.0 tag. Nothing held the SDKs' own public API. A rename or a
removed argument in an SDK reached integrators with no check noticing, and the
planned removal of the SDKs' test switches would have renamed and removed exported
symbols in exactly that way.

## Decision

1. Each SDK has an API gate, `scripts/gates/gate-api-<sdk>.sh`, which runs like
   every other gate: through `scripts/gates/ratchet.py`, against a shrink-only
   baseline, from `scripts/gates/run.sh`, `scripts/ci-local.sh` and
   `.github/workflows/gates.yml`. Its tool is pinned to an exact version, at least
   two weeks old when it was pinned, and installed by the gates' installers:
   - Go: `apidiff` (`golang.org/x/exp/cmd/apidiff`), over every package under
     `sdk/go` that is not internal. `golang.org/x/exp` has no releases, so the pin
     is a pseudo-version, one commit of that module (`scripts/gates/go-tools.sh`).
2. The gate compares the SDK's public API in the tree with the API of the last
   release: the newest `vX.Y.Z` tag reachable from HEAD. A release tag is what
   integrators installed, so compatibility is measured from it, not from the base
   of a pull request: against the base, a break made across several merges would
   pass each time. `--base-ref` reaches only the ratchet's own check that a baseline
   did not grow. Without a reachable release tag the gate fails and says how to
   fetch the tags; it never compares against anything else. CI's checkouts fetch
   the whole history with its tags.
3. An incompatible change to an exported symbol, as the SDK's tool classifies it
   (a removal, a rename, a changed signature), fails. A compatible addition passes.
   A rename passes when the old name stays, with its old signature, as an alias
   that calls the new one and is marked deprecated in the language's own way (Go: a
   `// Deprecated:` paragraph in its doc comment). The tool then reports no change
   to the old name, so the deprecation needs no exception in the gate.
4. The one exception: the release the change goes into is a major version, and
   the SDK's changelog (`sdk/<sdk>/CHANGELOG.md`) lists the symbol under a
   `### Breaking` heading in its first `## ` section, which is headed `Unreleased`
   or with the new version. The symbol is written in backticks, spelled as the gate
   prints it. Old names are deprecated within a major version and removed in the
   next one.
5. The gate learns the release's version from the manifest the release tooling
   holds to the tag (`scripts/release/check-versions.py`, `RELEASING.md`): the
   repository's `package.json` for the Go module, which has no manifest of its own.
   The release is a major version when that version's major is above the major
   of the last release tag. A release-preparation change raises the version, so
   every change merged after it, until the tag, goes into that release.
6. A finding names the symbol, not a line, so its identity does not move with
   edits elsewhere. Each baseline was recorded empty: the last release, v1.2.1,
   and the tree the gates were added to differ only by additions.
7. The scope gate counts each SDK's public surface as read: `SURFACES` in
   `scripts/gates/scope.py` declares the files each API gate must read, and the
   gate fails when an API gate reads a different set.

## Consequences

- Removing or renaming an exported symbol within a major version takes two
  steps: add the new name and deprecate the old one now, and remove the old one in
  the next major release, listed under Breaking.
- A Go major release also changes the module path (`/v2`), as Go modules require
  of a major version above 1; the gate does not prepare that change.
- A clone without the release tags cannot run the API gates. `git fetch --tags`
  from the repository's remote fixes it.
- After a release, the comparison moves to the new tag on its own; nothing in the
  repository is updated.
