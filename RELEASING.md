# Releasing FORA

This repository uses unified versioning. Each immutable `vX.Y.Z` tag identifies the
source commit for the Go module and the npm and PyPI packages carrying version
`X.Y.Z`:

- Go module: `github.com/FORA-Protocol/protocol@vX.Y.Z`
- npm package: `@fora-protocol/sdk@X.Y.Z`
- PyPI packages: `fora-protocol==X.Y.Z` and `fora-protocol-sdk==X.Y.Z`

A change may affect only one SDK. Under unified versioning, every released manifest
still advances to the new version; unchanged packages are rebuilt and published from
the same tagged commit.

The [`release` workflow](.github/workflows/release.yml) runs when a `v*` tag is
pushed. It checks the version, reruns CI on the tagged commit, builds and smoke-tests
the artifacts, stores them in the GitHub Release, publishes the exact same files, and
then installs them from the registries. Never move or delete a release tag.

The repository owners maintain the GitHub environment, protected-tag rules, and
registry trusted publishers. This runbook starts after that setup is complete.

## Prepare a release

Create a release branch for the version:

```bash
git switch main
git pull --ff-only
git switch -c release/vX.Y.Z
```

Update these authored version values to `X.Y.Z`:

| File | Value |
| --- | --- |
| `package.json` | `version` |
| `gen/ts/package.json` | `version` |
| `sdk/ts/package.json` | `version` |
| `gen/python/pyproject.toml` | `project.version` |
| `sdk/python/pyproject.toml` | `project.version` |
| `sdk/python/pyproject.toml` | the exact `fora-protocol==X.Y.Z` dependency |

Do not change `website/package.json`; the website has an independent version.

Use npm to update each TypeScript manifest and its lockfile together:

```bash
(cd gen/ts && npm version X.Y.Z --no-git-tag-version)
(cd sdk/ts && npm version X.Y.Z --no-git-tag-version)
```

After editing `gen/python/pyproject.toml` and `sdk/python/pyproject.toml`, regenerate
the SDK lockfile:

```bash
uv lock --project sdk/python
```

Check the result from the repository root:

```bash
python3 scripts/release/check-versions.py X.Y.Z
git diff --check
git diff
```

Open a pull request, wait for every required check to pass, review the built-package
changes, and merge it. Do not create the tag from the release branch.

## Create the release

After the release-preparation pull request is merged, update local `main` and verify
the version gate once more:

```bash
git switch main
git pull --ff-only
python3 scripts/release/check-versions.py X.Y.Z
git status --short
```

The working tree must be clean. Create an annotated tag on that exact commit and push
only the tag:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

Open the resulting `release` workflow in GitHub Actions. Review the version, CI, and
build jobs, then approve the `release` environment deployment. Confirm that the
publish and final verification jobs pass.

## Verify the release

The workflow performs these checks. They can also be run manually after publication:

```bash
npm view @fora-protocol/sdk@X.Y.Z name version dist.integrity --json
scripts/release/smoke-npm.sh "@fora-protocol/sdk@X.Y.Z"

scripts/release/smoke-python.sh "fora-protocol-sdk==X.Y.Z"

GOPROXY=https://proxy.golang.org go list -m \
  "github.com/FORA-Protocol/protocol@vX.Y.Z"
```

Also confirm that the GitHub Release contains exactly the files listed by
`scripts/release/files.sh X.Y.Z` plus `SHA256SUMS`.

## Recover a failed release

Never move, delete, or recreate the tag. Fix external configuration if necessary,
then rerun the failed workflow for the same tag.

The release scripts are idempotent per file:

- existing GitHub Release assets are verified against `SHA256SUMS` and not rebuilt;
- an existing registry file with the expected digest is skipped;
- a missing registry file is published;
- a digest mismatch or registry lookup failure stops the release.

The npm and PyPI publish jobs are independent. If one registry succeeds and the other
fails, rerunning the same workflow verifies and skips the successful files before
retrying the missing ones.
