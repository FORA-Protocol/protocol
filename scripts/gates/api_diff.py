#!/usr/bin/env python3
"""Print the incompatible changes to one SDK's public API since the last release.

The last release is the newest vX.Y.Z tag reachable from HEAD (api_rules.py). This
script builds what the SDK's tool needs from that tag, runs the tool over the tag
and the tree, and prints the tool's own output, which api_formats.py reads. It is
the command each API gate (scripts/gates/gate-api-*.sh) runs through ratchet.py.
It names the tag it compares against on stderr, and exits non-zero, printing why,
when the tag cannot be found or a tool fails.

  go: apidiff, over every non-internal package under GO_PACKAGES (sdk/go). The
      tagged tree is extracted with `git archive`, apidiff writes its export data
      there, and `apidiff -m -incompatible` compares it with the tree.
  python: griffe check, over the public API of PYTHON_PACKAGE (fora_sdk), found
      under PYTHON_SEARCH_PATH (sdk/python); griffe checks the tag out itself.
      Its breakages, which it writes on stderr, are printed on stdout, and its
      exit code, 1 when it reports a breakage, is this script's.
  ts: API Extractor, over every entry point of sdk/ts/package.json's export map.
      tsc writes the declarations of the tagged tree and of the tree, and
      scripts/gates/api-extractor.mjs generates each entry point's report from
      them; for the tree, it also compares each report with the one committed
      under sdk/ts/api. One JSON line per entry point holds API Extractor's
      messages about the tree and the report at the tag (`base`) and in the tree
      (`head`); a committed report no entry point has gets a line of its own.

Usage:  api_diff.py go|python|ts
        api_diff.py ts --update    rewrite sdk/ts/api from the tree
"""

from __future__ import annotations

import json
import re
import sys
import tarfile
import tempfile
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING

import scope
from api_rules import ReleaseError, last_release
from scope import REPO_ROOT

if TYPE_CHECKING:
    import subprocess
    from typing import Any

# A log line of griffe, which writes it beside its breakages: `LEVEL     message`.
GRIFFE_LOG = re.compile(r"^(?:DEBUG|INFO|WARNING|ERROR|CRITICAL)\s")

# What `git archive` leaves out of the tagged tree: the documentation site, which no
# SDK build reads.
ARCHIVE_EXCLUDE = ":(exclude)website"


# What the Go and Python tools read. go() and python() build their command lines from
# these alone, and the scope gate (scope_coverage.py) reads them to name the files those
# gates read, so a change here is a change the scope gate sees.
# The Go packages apidiff compares: every package under this directory of the module.
GO_PACKAGES = "sdk/go"
# The Python package griffe checks, and the directory griffe finds it in.
PYTHON_PACKAGE = "fora_sdk"
PYTHON_SEARCH_PATH = "sdk/python"


def module_path(gomod: Path) -> str:
    """Return the module path the go.mod file `gomod` declares."""
    for line in gomod.read_text(encoding="utf-8").splitlines():
        if line.startswith("module "):
            return line.split()[1]
    raise ValueError(f"{gomod} declares no module")


@cache
def go_module() -> str:
    """Return the module path the tree's go.mod declares."""
    return module_path(REPO_ROOT / "go.mod")


def go_packages(module: str) -> str:
    """Return the argument that names GO_PACKAGES to `apidiff -m` within the module `module`."""
    return f"{module}/{GO_PACKAGES}"


class ToolError(Exception):
    """A tool the comparison runs failed; the message says which and how."""


def run(
    argv: list[str], cwd: Path = REPO_ROOT, ok: tuple[int, ...] = (0,)
) -> subprocess.CompletedProcess[str]:
    """Run `argv` in `cwd`, and raise ToolError when it exits with a code not in `ok`."""
    proc = scope.run(argv, cwd)
    if proc.returncode not in ok:
        raise ToolError(
            f"{' '.join(argv[:3])} exited {proc.returncode}:\n{proc.stdout}{proc.stderr}"
        )
    return proc


def extract(tag: str, into: Path) -> None:
    """Write the tree of `tag`, without the documentation site, into `into`."""
    tar = into.with_suffix(".tar")
    run(["git", "archive", "--format=tar", "-o", str(tar), tag, "--", ".", ARCHIVE_EXCLUDE])
    try:
        with tarfile.open(tar) as archive:
            archive.extractall(into, filter="data")
    except tarfile.TarError as exc:
        raise ToolError(f"cannot extract the tree of {tag}: {exc}") from exc


def quiet(stderr: str) -> str:
    """Return apidiff's stderr without the line it prints for each internal package it skips."""
    return "".join(
        line
        for line in stderr.splitlines(keepends=True)
        if not line.startswith("Ignoring internal package")
    )


def go(tag: str) -> tuple[str, int]:
    packages = go_packages(go_module())
    with tempfile.TemporaryDirectory() as tmp:
        old, export = Path(tmp) / "tree", Path(tmp) / "old.zip"
        extract(tag, old)
        written = run(["apidiff", "-m", "-w", str(export), packages], old)
        sys.stderr.write(quiet(written.stderr))
        compared = run(["apidiff", "-m", "-incompatible", str(export), packages])
    sys.stderr.write(quiet(compared.stderr))
    return compared.stdout, 0


def python(tag: str) -> tuple[str, int]:
    """Return griffe's breakages and its exit code.

    griffe check prints its breakages on stderr, with its log lines, which begin
    with their level; the breakages are returned and the log is passed on.
    """
    griffe = str(REPO_ROOT / "sdk/python/.venv/bin/griffe")
    argv = [griffe, "check", PYTHON_PACKAGE, "-s", PYTHON_SEARCH_PATH, "-a", tag]
    argv += ["-f", "oneline"]
    proc = run([*argv, "--no-color"], ok=(0, 1))
    lines = proc.stderr.splitlines(keepends=True)
    sys.stderr.write(proc.stdout + "".join(line for line in lines if GRIFFE_LOG.match(line)))
    return "".join(line for line in lines if not GRIFFE_LOG.match(line)), proc.returncode


REPORTS = "sdk/ts/api"
TS_MODULES = "sdk/ts/node_modules"


def declarations(tree: Path, dts: Path) -> None:
    """Write the declarations of the TypeScript SDK's entry points in `tree` into `dts`.

    tsc reads `tree`'s own sdk/ts/tsconfig.json, with the targets of its export map as
    the root files, and the Node types of this checkout. The declarations of the
    files they import are written too, in `tree`'s layout.
    """
    manifest = json.loads((tree / "sdk/ts/package.json").read_text(encoding="utf-8"))
    options = {
        "noEmit": False,
        "declaration": True,
        "emitDeclarationOnly": True,
        "allowJs": False,
        "checkJs": False,
        "types": ["node"],
        "typeRoots": [str(REPO_ROOT / TS_MODULES / "@types")],
        "rootDir": str(tree),
        "outDir": str(dts),
    }
    config = dts.with_suffix(".tsconfig.json")
    config.write_text(
        json.dumps(
            {
                "extends": str(tree / "sdk/ts/tsconfig.json"),
                "compilerOptions": options,
                "include": [],
                "files": [str(tree / "sdk/ts" / t) for t in manifest["exports"].values()],
            }
        )
    )
    run([str(REPO_ROOT / TS_MODULES / ".bin/tsc"), "-p", str(config)])


def extracted(mode: str, tree: Path, work: Path, reports: Path) -> list[dict[str, Any]]:
    """Return the line api-extractor.mjs prints for each entry point of `tree`."""
    work.mkdir(parents=True, exist_ok=True)
    dts = work / "dts"
    declarations(tree, dts)
    driver = ["node", "scripts/gates/api-extractor.mjs", mode, str(tree), str(dts), str(reports)]
    return [json.loads(line) for line in run(driver).stdout.splitlines() if line.strip()]


def committed_reports() -> set[str]:
    return {p.relative_to(REPO_ROOT).as_posix() for p in (REPO_ROOT / REPORTS).rglob("*.api.md")}


def ts(tag: str) -> tuple[str, int]:
    with tempfile.TemporaryDirectory() as tmp:
        old = Path(tmp) / "tree"
        extract(tag, old)
        # The tagged tree resolves its packages against this checkout's.
        (old / TS_MODULES).symlink_to(REPO_ROOT / TS_MODULES)
        base = extracted("write", old, Path(tmp) / "old", Path(tmp) / "old-reports")
        head = extracted("check", REPO_ROOT, Path(tmp) / "new", REPO_ROOT / REPORTS)
    failed = [m for row in base for m in row["messages"] if m["category"] == "Compiler"]
    if failed:
        raise ToolError(f"API Extractor could not analyze {tag}: {failed}")
    old_text = {row["entry"]: row["text"] for row in base}
    rows = []
    for row in head:
        report = f"{REPORTS}/{row['report']}"
        base_text = old_text.pop(row["entry"], None)
        rows.append({**row, "report": report, "base": base_text, "head": row["text"]})
    for entry, text in sorted(old_text.items()):
        report = f"{REPORTS}/{entry.removeprefix('./')}.api.md"
        rows.append({"entry": entry, "report": report, "messages": [], "base": text, "head": None})
    for orphan in sorted(committed_reports() - {r["report"] for r in rows}):
        message = {
            "id": "orphaned-report",
            "text": "no entry point of sdk/ts/package.json has this report",
        }
        rows.append({"entry": None, "report": orphan, "messages": [message]})
    return "".join(json.dumps(r) + "\n" for r in rows), 0


def update() -> None:
    """Write the API report of every entry point of the tree into sdk/ts/api, and nothing else."""
    for report in committed_reports():
        (REPO_ROOT / report).unlink()
    with tempfile.TemporaryDirectory() as tmp:
        rows = extracted("write", REPO_ROOT, Path(tmp), REPO_ROOT / REPORTS)
    failed = [m for row in rows for m in row["messages"] if m["category"] == "Compiler"]
    if failed:
        raise ToolError(f"API Extractor could not analyze the tree: {failed}")
    sys.stderr.write(f"api_diff: wrote {len(rows)} API reports into {REPORTS}\n")


SDKS = {"go": go, "python": python, "ts": ts}


def main(argv: list[str]) -> int:
    if argv == ["ts", "--update"]:
        try:
            update()
        except ToolError as exc:
            sys.stderr.write(f"api_diff: {exc}\n")
            return 1
        return 0
    if len(argv) != 1 or argv[0] not in SDKS:
        sys.stderr.write(f"usage: api_diff.py {'|'.join(SDKS)}, or api_diff.py ts --update\n")
        return 2
    try:
        tag = last_release()
        sys.stderr.write(f"api_diff: comparing the {argv[0]} SDK's public API against {tag}\n")
        out, code = SDKS[argv[0]](tag)
    except (ReleaseError, ToolError) as exc:
        sys.stderr.write(f"api_diff: {exc}\n")
        return 1
    sys.stdout.write(out)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
