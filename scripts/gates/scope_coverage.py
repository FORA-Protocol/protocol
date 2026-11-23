#!/usr/bin/env python3
"""Check that every gate reads exactly the hand-written files of its languages.

scope.py defines the hand-written code and, in GATES, which gates read each
language. This script asks each gate's tool which files it reads, the way the
gate runs it, and prints one problem per line:

- a hand-written file that a gate of its language does not read;
- a generated file, or a file outside the scope, that a gate reads as one of its
  own files;
- an entry of scope.GENERATED that matches no tracked file, a listed file with no
  generated header, and a file with a generated header that GENERATED does not
  list;
- a file of an API gate's public surface (scope.SURFACES) that the gate does not
  read, and a file the gate reads that is outside that surface.

How each tool's files are found:
- go-lint and go-format: golangci-lint reads the packages of `./...`, which
  `go list` names with every file of each package, minus the paths that the
  `exclusions` of the linters and of the formatters in .golangci.yml remove.
  golangci-lint has no file listing, so this is derived from its config.
- python-lint: `ruff check --show-files` over the files the Python gates pass,
  which are `scope.py files --language python`. python-format: `ruff format`
  has no listing; it reads the same files, because ruff.toml has no format-only
  exclusion (checked here).
- python-types: the sources `mypy -v` reports it found among the same files.
- ts-format and ts-lint: the files biome reports processing (`--verbose`), run
  with the command the gate runs.
- ts-types: the root files of each tsc project gate-ts-types.sh passes to
  tsc-projects.sh, from `tsc --showConfig`. A file a project imports is read for
  its types and is not counted, so a generated module an SDK file imports is not
  a problem.
- duplication: the files of jscpd's report (statistics.formats.*.sources), run
  through scripts/gates/jscpd-report.sh as the gate runs it.
  jscpd leaves a one-line file out of its report; a file shorter than the
  smallest clone .jscpd.json reports (minLines) cannot hold one, so such a file
  is not required there.
- file-length and inline-suppressions: their scanners read scope.sources(), so
  they read exactly the scope by construction and are not asked.
- api-go: apidiff loads the packages of `MODULE/sdk/go/...` and skips the internal
  ones, by the rule of its isInternalPackage. `go list` names the files the build
  selects in each package, which are the files apidiff type-checks. apidiff has no
  file listing, so this is derived from the package pattern api_diff.py passes.
- api-python: the module files `griffe dump fora_sdk -s sdk/python` reports, the
  package api_diff.py passes to `griffe check`.
- api-ts: the entry points api-extractor.mjs reports reading (`source`), run over
  the tree as the gate runs it.

Usage:  scope_coverage.py   (prints the problems; exits 1 when there is one)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

from api_diff import REPORTS, extracted
from scope import (
    GATES,
    LANGUAGES,
    REPO_ROOT,
    check_generated,
    gated_files,
    generated_by,
    hand_written,
    read,
    surface,
)
from toolfiles import tool_args

VENV = "sdk/python/.venv/bin"
NODE = "sdk/ts/node_modules/.bin"
JSCPD = "scripts/gates/node_modules/.bin/jscpd"


def run(argv: list[str], *, ok: tuple[int, ...] = (0, 1)) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(argv, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    if proc.returncode not in ok:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f"scope_coverage: {' '.join(argv[:3])} exited {proc.returncode}")
    return proc


def rel(path: str, base: Path = REPO_ROOT) -> str:
    p = (base / path).resolve()
    try:
        return p.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return p.as_posix()


def golangci_exclusions() -> dict[str, list[re.Pattern[str]]]:
    """Return the `exclusions.paths` regexes of the linters and of the formatters.

    The config is read line by line: a `paths:` key under a top-level section,
    followed by its list items, or by an alias (`*name`) of a list anchored
    (`&name`) earlier.
    """
    found: dict[str, list[re.Pattern[str]]] = {"linters": [], "formatters": []}
    anchors: dict[str, list[re.Pattern[str]]] = {}
    section, current = "", None
    for line in (REPO_ROOT / ".golangci.yml").read_text().splitlines():
        if re.match(r"^\w", line):
            section, current = line.split(":")[0], None
        m = re.match(r"^\s+paths:\s*(?:&(\S+)|\*(\S+))?\s*$", line)
        if m and section in found:
            current = found[section] if m[2] is None else None
            if m[2] is not None:
                found[section].extend(anchors[m[2]])
            if m[1]:
                anchors[m[1]] = found[section]
            continue
        item = re.match(r"^\s+- ['\"](.*)['\"]\s*$", line)
        if item and current is not None:
            current.append(re.compile(item[1]))
        elif not re.match(r"^\s*(#|$)", line):
            current = None
    return found


def go_files() -> dict[str, set[str]]:
    """Return the files the linters and the formatters read.

    The linters type-check packages, so they read the files the build selects.
    The formatters read every Go file of a package directory, those a build
    constraint leaves out (IgnoredGoFiles) too.
    """
    built = "{{.GoFiles}}{{.CgoFiles}}{{.TestGoFiles}}{{.XTestGoFiles}}"
    out = run(
        ["go", "list", "-f", "{{.Dir}}\t" + built + "\t{{.IgnoredGoFiles}}", "./..."], ok=(0,)
    )
    linted, formatted = set(), set()
    for line in out.stdout.splitlines():
        directory, names, ignored = line.split("\t")
        files = {rel(f"{directory}/{n}") for n in re.findall(r"[^\[\] ]+\.go", names)}
        linted |= files
        formatted |= files | {
            rel(f"{directory}/{n}") for n in re.findall(r"[^\[\] ]+\.go", ignored)
        }
    excluded = golangci_exclusions()
    return {
        "go-lint": {f for f in linted if not any(p.search(f) for p in excluded["linters"])},
        "go-format": {f for f in formatted if not any(p.search(f) for p in excluded["formatters"])},
    }


def python_files() -> dict[str, set[str]]:
    helper = (REPO_ROOT / "scripts/gates/python-tools.sh").read_text()
    if "scope.py files --language python" not in helper:
        raise SystemExit(
            "scope_coverage: python-tools.sh does not pass `scope.py files --language python`, "
            "so the files the Python gates read are not known"
        )
    ruff_toml = tomllib.loads((REPO_ROOT / "ruff.toml").read_text())
    if {"exclude", "extend-exclude"} & set(ruff_toml.get("format", {})):
        raise SystemExit("scope_coverage: ruff.toml excludes files from ruff format alone")
    given = hand_written(["python"])
    shown = run([f"{VENV}/ruff", "check", "--show-files", *given]).stdout
    ruff = {rel(line.strip()) for line in shown.splitlines() if line.strip()}
    log = run([f"{VENV}/mypy", "--config-file", "mypy.ini", "-v", *given]).stderr
    mypy = {rel(p) for p in re.findall(r"Found source:\s+BuildSource\(path='([^']+)'", log)}
    return {"python-lint": ruff, "python-format": ruff, "python-types": mypy}


def biome_files(argv: list[str]) -> set[str]:
    out = run([f"{NODE}/biome", *argv, "--verbose", "--max-diagnostics=0"]).stdout
    block = out.split("Files processed:", 1)[-1] if "Files processed:" in out else ""
    return {rel(m) for m in re.findall(r"^\s+- (\S+)$", block, re.MULTILINE)}


def tsc_files() -> set[str]:
    gate = (REPO_ROOT / "scripts/gates/gate-ts-types.sh").read_text()
    # The words after tsc-projects.sh: the path of tsc, then the projects. A tsconfig
    # the gate passes only as a --tool-file, such as one the projects extend, has no
    # files of its own to check.
    projects = sorted(set(tool_args(gate, "scripts/gates/tsc-projects.sh")[1:]))
    files = set()
    for project in projects:
        config = json.loads(run([f"{NODE}/tsc", "-p", project, "--showConfig"], ok=(0,)).stdout)
        base = (REPO_ROOT / project).parent
        files |= {rel(f, base) for f in config.get("files", [])}
    return files


def jscpd_files() -> set[str]:
    """Return the files jscpd reads, with every hand-written file too short for a clone."""
    min_lines = int(json.loads((REPO_ROOT / ".jscpd.json").read_text())["minLines"])
    short = {p for p in hand_written([]) if read(p).count("\n") < min_lines}
    # The gate's own runner, so this reads what the gate reads.
    report = json.loads(run(["bash", "scripts/gates/jscpd-report.sh", JSCPD]).stdout)
    formats = report["statistics"]["formats"].values()
    return short | {rel(source) for f in formats for source in f["sources"]}


def is_internal(import_path: str) -> bool:
    """Return whether apidiff skips the package `import_path` as internal."""
    return "internal" in import_path.split("/")


def api_go_files() -> set[str]:
    driver = (REPO_ROOT / "scripts/gates/api_diff.py").read_text()
    if 'f"{go_module()}/sdk/go"' not in driver:
        raise SystemExit("scope_coverage: api_diff.py does not compare MODULE/sdk/go")
    module = run(["go", "list", "-m"], ok=(0,)).stdout.strip()
    built = "{{.ImportPath}}\t{{.Dir}}\t{{.GoFiles}}{{.CgoFiles}}"
    out = run(["go", "list", "-f", built, f"{module}/sdk/go/..."], ok=(0,)).stdout
    files = set()
    for line in out.splitlines():
        path, directory, names = line.split("\t")
        if not is_internal(path):
            files |= {rel(f"{directory}/{n}") for n in re.findall(r"[^\[\] ]+\.go", names)}
    return files


def module_files(node: object) -> set[str]:
    """Return the `filepath` of every module in a `griffe dump` tree."""
    if isinstance(node, list):
        return {f for child in node for f in module_files(child)}
    if not isinstance(node, dict):
        return set()
    found = (
        {rel(node["filepath"])} if node.get("kind") == "module" and "filepath" in node else set()
    )
    return found.union(*(module_files(child) for child in node.values()))


def api_python_files() -> set[str]:
    driver = (REPO_ROOT / "scripts/gates/api_diff.py").read_text()
    if '"check", "fora_sdk", "-s", "sdk/python"' not in driver:
        raise SystemExit("scope_coverage: api_diff.py does not check fora_sdk under sdk/python")
    dump = run([f"{VENV}/griffe", "dump", "fora_sdk", "-s", "sdk/python"], ok=(0,)).stdout
    return module_files(json.loads(dump))


def api_ts_files() -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        rows = extracted("check", REPO_ROOT, Path(tmp), REPO_ROOT / REPORTS)
    return {row["source"] for row in rows}


def api_files() -> dict[str, set[str]]:
    """Return the files each API gate reads as its public surface."""
    return {"api-go": api_go_files(), "api-python": api_python_files(), "api-ts": api_ts_files()}


def surface_problems(read: dict[str, set[str]]) -> list[str]:
    """Return each file an API gate misses from its surface, or reads outside it."""
    out = []
    for gate, files in sorted(read.items()):
        expected = set(surface(gate))
        out += [
            f"{p}: public surface of {gate}, but {gate} does not read it"
            for p in sorted(expected - files)
        ]
        out += [
            f"{p}: {gate} reads it, but it is not in its public surface"
            for p in sorted(files - expected)
        ]
    return out


def gate_files() -> dict[str, set[str]]:
    files = {**go_files(), **python_files()}
    files["ts-format"] = biome_files(["format"])
    files["ts-lint"] = biome_files(["check", "--formatter-enabled=false"])
    files["ts-types"] = tsc_files()
    files["duplication"] = jscpd_files()
    return files


def problems(read: dict[str, set[str]]) -> list[str]:
    """Return each file a gate misses or reads that it should not, against the scope."""
    out = []
    languages = dict(gated_files())
    for path, language in sorted(languages.items()):
        listed = generated_by(path)
        for gate in sorted(read):
            if listed is not None and path in read[gate]:
                out.append(f"{path}: generated ({listed}), but {gate} reads it")
            elif listed is None and gate in GATES[language] and path not in read[gate]:
                out.append(f"{path}: hand-written {language}, but {gate} does not read it")
    for gate, files in sorted(read.items()):
        out += [
            f"{path}: {gate} reads it, but it is not a tracked file in scope"
            for path in sorted(files - languages.keys())
            if Path(path).suffix in LANGUAGES
        ]
    return out


def main() -> int:
    found = check_generated() + problems(gate_files()) + surface_problems(api_files())
    for line in found:
        print(line)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
