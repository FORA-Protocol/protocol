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

A tag can also name a prerelease, `vX.Y.Z-beta.N` or `vX.Y.Z-rc.N`. The release
workflow refuses any other tag. See [Prereleases](#prereleases) for how a
prerelease differs.

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
| `gen/python/pyproject.toml` | `project.version` |
| `sdk/python/pyproject.toml` | `project.version` |
| `sdk/python/pyproject.toml` | the exact `fora-protocol==X.Y.Z` dependency |

Do not change `website/package.json`; the website has an independent version.

Use npm to update each TypeScript manifest and its lockfile together. Do not edit
these two `package.json` files first:

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
uv run --no-project --python '>=3.11' python scripts/release/check-versions.py X.Y.Z
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
uv run --no-project --python '>=3.11' python scripts/release/check-versions.py X.Y.Z
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

The workflow's verify job runs these checks. They can also be run manually after
publication. Each script takes the tag and derives each ecosystem's spelling from it:

```bash
scripts/release/verify-pypi.sh vX.Y.Z
scripts/release/verify-npm.sh vX.Y.Z
scripts/release/verify-github-release.sh vX.Y.Z

GOPROXY=https://proxy.golang.org go list -m \
  "github.com/FORA-Protocol/protocol@vX.Y.Z"
```

`verify-pypi.sh` installs the SDK wheel from PyPI and rebuilds both sdists.
`verify-npm.sh` waits for the version on npm, checks that its dist-tag points at it,
and installs the package. `verify-github-release.sh` checks the release's prerelease
mark.

Also confirm that the GitHub Release contains exactly the files listed by
`scripts/release/files.sh X.Y.Z` plus `SHA256SUMS`.

## Prereleases

A prerelease follows the same steps as a final release, with two differences: the
version has a different spelling in each ecosystem, and the packages do not become
the default install.

Go and npm use the tag's version. Python uses the
[PEP 440](https://peps.python.org/pep-0440/) normalized form of the same version:

| Tag | Go module | npm | PyPI |
| --- | --- | --- | --- |
| `v1.3.0-beta.1` | `v1.3.0-beta.1` | `1.3.0-beta.1` | `1.3.0b1` |
| `v1.3.0-rc.1` | `v1.3.0-rc.1` | `1.3.0-rc.1` | `1.3.0rc1` |
| `v1.3.0` | `v1.3.0` | `1.3.0` | `1.3.0` |

`scripts/release/version.py` prints each spelling, for example
`scripts/release/version.py v1.3.0-beta.1 python` prints `1.3.0b1`. The release
workflow passes the tag unchanged to every release script, and each script derives
the spelling it needs from `version.py`, which takes the tag with or without its
`v`. No step strips or rewrites the tag itself.

When you prepare a prerelease, write the npm spelling in the root `package.json`
`version` and, through `npm version` as above, in `gen/ts` and `sdk/ts`. Write the
PyPI spelling in the two `pyproject.toml` files and in the `fora-protocol==` pin. For
`v1.3.0-beta.1`:

```bash
(cd gen/ts && npm version 1.3.0-beta.1 --no-git-tag-version)
(cd sdk/ts && npm version 1.3.0-beta.1 --no-git-tag-version)
# package.json: "version": "1.3.0-beta.1"
# gen/python/pyproject.toml and sdk/python/pyproject.toml: version = "1.3.0b1"
# sdk/python/pyproject.toml: "fora-protocol==1.3.0b1"
uv lock --project sdk/python
uv run --no-project --python '>=3.11' python scripts/release/check-versions.py 1.3.0-beta.1
```

The version gate takes the tag's version and fails if any manifest uses the other
ecosystem's spelling.

Merging the preparation pull request also changes the documentation site built from
`main`. The site shows the root `package.json` version as the SDK version
(`:sdk-version`, `website/plugins/remark-version.mjs`), so it shows the npm spelling,
`1.3.0-beta.1`, which PEP 440 also reads as the PyPI version `1.3.0b1`.

Then tag and push as for a final release (`git tag -a v1.3.0-beta.1 -m
"v1.3.0-beta.1"`). Two things differ from a final release:

- npm publishes the prerelease under the dist-tag `next`. The `latest` dist-tag stays
  on the newest final release, so `npm install @fora-protocol/sdk` does not install the
  prerelease. Consumers install it with `@fora-protocol/sdk@next` or the exact version.
  A final release is published under `latest`, and only when npm has no final
  version above it, so `latest` never moves back (see
  [Recover a failed release](#recover-a-failed-release)).
- The GitHub Release is marked as a prerelease.

pip and uv skip prereleases unless a requirement names one, so a plain
`fora-protocol-sdk` installs the newest final release, not the prerelease. pip installs
`fora-protocol-sdk==1.3.0b1` and takes `fora-protocol==1.3.0b1` through the SDK's
exact pin, and so does uv from 0.12.0 on, which includes the 0.12.11 the release
workflow pins (`.github/actions/setup-uv`). uv before 0.12.0 accepts a prerelease only
for a package the install itself names, so it refuses that pin unless `fora-protocol`
is named too, for example
`uv pip install fora-protocol-sdk==1.3.0b1 fora-protocol==1.3.0b1`. uv 0.12.0 changed
this; its release notes list it as "Prefer stable releases before falling back to
pre-releases". `verify-pypi.sh` names `fora-protocol` as a constraint, for a final
release too, so it passes under an older uv run by hand as well, while the SDK's pin
still has to pull it in. Go selects a prerelease only when it is requested: `go get
github.com/FORA-Protocol/protocol@v1.3.0-beta.1`.

The verify scripts take a prerelease tag like any other, for example
`scripts/release/verify-npm.sh v1.3.0-beta.1`. For a prerelease, `verify-npm.sh` also
checks that `latest` does not point at it, and `verify-github-release.sh` checks that
the release is marked as a prerelease.

## Recover a failed release

Never move, delete, or recreate the tag. If external configuration caused the
failure, fix it and rerun the failed workflow for the same tag. If the tagged
workflow or release code is defective, fix it in a pull request and release the
next patch version.

The release scripts are idempotent per file:

- existing GitHub Release assets are verified against `SHA256SUMS` and not rebuilt;
- an existing registry file with the expected digest is skipped;
- a missing registry file is published, except an npm final release below a final
  npm already has;
- a digest mismatch or registry lookup failure stops the release.

The npm and PyPI publish jobs are independent. If one registry succeeds and the other
fails, rerunning the same workflow verifies and skips the successful files before
retrying the missing ones.

npm's `latest` dist-tag is a pointer that each publish under it moves, so the release
refuses a final version below a final npm already has, a deprecated one included. The
build job refuses it before it creates the GitHub Release, and the npm publish refuses
it again. There is no maintenance line: a patch to an older line cannot be released
through this workflow. PyPI and Go need no such check, because they pick the highest
version rather than follow a pointer. The same check fails a pull request's dry run
(`sdk-types-ci.yml`) when the branch the pull request merges into still carries a
version below npm's newest final; merging `main` into that branch clears it.
