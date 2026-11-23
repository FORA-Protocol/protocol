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
  list.

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
- ts-types: the root files of each tsc project gate-ts-types.sh names, from
  `tsc --showConfig`. A file a project imports is read for its types and is not
  counted, so a generated module an SDK file imports is not a problem.
- duplication: the files of jscpd's report (statistics.formats.*.sources), run
  through scripts/gates/jscpd-report.sh as the gate runs it.
  jscpd leaves a one-line file out of its report; a file shorter than the
  smallest clone .jscpd.json reports (minLines) cannot hold one, so such a file
  is not required there.
- file-length and inline-suppressions: their scanners read scope.sources(), so
  they read exactly the scope by construction and are not asked.

Usage:  scope_coverage.py   (prints the problems; exits 1 when there is one)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from scope import (
    GATES,
    LANGUAGES,
    REPO_ROOT,
    check_generated,
    gated_files,
    generated_by,
    hand_written,
    read,
)

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
    projects = sorted(set(re.findall(r"[\w./-]+/tsconfig[\w.]*\.json", gate)))
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
    found = check_generated() + problems(gate_files())
    for line in found:
        print(line)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
