"""Tests for inline_suppressions.py, run through its command line.

Each test copies the gate modules into a throwaway git repository, writes and
stages source files, and reads the rows the script prints. The markers are
assembled from parts, so this file holds no suppression of its own.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from typing import TYPE_CHECKING

from inline_suppressions import KINDS
from ratchet_harness import GATES, GateRepo, RatchetRepo
from scope import GATES as LANGUAGE_GATES
from scope import LANGUAGES, lines

if TYPE_CHECKING:
    import subprocess

SLASHES = "/" * 2
HASH = "#"
TS = "@ts-"
NOLINT = f"{SLASHES}nolint:errcheck"
NOSEC = f"{SLASHES} {HASH}nosec G104"
NOQA = f"{HASH} noqa: S101"
TYPE_IGNORE = f"{HASH} type: ignore[arg-type]"
BIOME_IGNORE = f"{SLASHES} biome-ignore lint/style/noNonNullAssertion: reason"
TS_IGNORE = f"{SLASHES} {TS}ignore"
TS_EXPECT = f"{SLASHES} {TS}expect-error"
TS_NOCHECK = f"{SLASHES} {TS}nocheck"
ESLINT = "/* eslint-disable no-console */"
CAST = "const x = y as " + "unknown as Z;"
NO_TYPE_CHECK = "no_type_" + "check"
JSCPD = "jscpd:" + "ignore-"
# jscpd's markers in each place jscpd honors one, and in a string, where it does not,
# but which the scanner cannot tell from a comment that quotes one.
JSCPD_FORMS = [
    f"{SLASHES} {JSCPD}start",
    f"{HASH} {JSCPD}end",
    f"/* {JSCPD}start */",
    f"{HASH} `{JSCPD}end`",
    f'{HASH} see "{JSCPD}start"',
    f"{HASH} {JSCPD}starting x{JSCPD}end",
    f'x = "{JSCPD}start"',
]


def languages_read_by(gate: str) -> set[str]:
    """Return the languages whose gates in scope.py include `gate`."""
    return {language for language, gates in LANGUAGE_GATES.items() if gate in gates}


# Each form a gated tool reads, with the kind the scanner reports it as.
GO_FORMS = [
    (f"\tg() {NOLINT}", "nolint"),
    (f"\tg() {SLASHES} /nolint:errcheck", "nolint"),
    (f"{SLASHES}lint:ignore U1000 reason", "lint-ignore"),
    (f"{SLASHES}lint:file-ignore U1000 reason", "lint-file-ignore"),
    (f"{SLASHES}revive:disable-next-line:argument-limit", "revive-disable"),
    (f"\tg() {SLASHES} revive:disable-line:argument-limit", "revive-disable"),
    (f"{SLASHES}gocognit:ignore", "gocognit-ignore"),
    (f"{SLASHES}gocyclo: ignore", "gocyclo-ignore"),
    (f"\tg() {SLASHES}gosec:disable G104", "gosec-disable"),
    (f"\tg() {NOSEC}", "nosec"),
    (f"\tg() /* {HASH}nosec */", "nosec"),
]
PYTHON_FORMS = [
    (f"x = 1  {NOQA}", "noqa"),
    (f"x = 1  {HASH} NOQA", "noqa"),
    (f"x = 1  {HASH}noqa:E501", "noqa"),
    (f"{HASH} ruff: noqa", "file-noqa"),
    (f"{HASH} ruff: noqa: F401", "file-noqa"),
    (f"{HASH} flake8: noqa", "file-noqa"),
    (f"x = 1  {HASH}ruff:ignore[E501]", "ruff-ignore"),
    (f"{HASH} ruff: file-ignore[F401]", "ruff-file-ignore"),
    (f"{HASH} ruff: disable[E501]", "ruff-disable"),
    (f"import os  {HASH} isort: skip", "isort-skip"),
    (f"import os  {HASH} keep isort: skip", "isort-skip"),
    (f"{HASH} isort: skip_file", "isort-skip"),
    (f"{HASH} ruff: isort: skip_file", "isort-skip"),
    (f"{HASH} isort: off", "isort-skip"),
    (f"{HASH} fmt: off", "fmt-off"),
    (f"x = [1,2]  {HASH} fmt: skip", "fmt-off"),
    (f"{HASH} yapf: disable", "yapf-disable"),
    (f"x = [1,2]  {HASH} yapf: disable", "yapf-disable"),
    (f"y = f(x)  {TYPE_IGNORE}", "type-ignore"),
    (f"y = f(x)  {HASH}type:ignore", "type-ignore"),
    (f"{HASH} mypy: ignore-errors", "mypy-config"),
    (f"{HASH} mypy: disable-error-code=arg-type", "mypy-config"),
    (f"@{NO_TYPE_CHECK}", "no-type-check"),
    (f"@typing.{NO_TYPE_CHECK}", "no-type-check"),
    (f"@t.{NO_TYPE_CHECK}", "no-type-check"),
    (f"from typing import {NO_TYPE_CHECK} as skip_types", "no-type-check"),
    (f"    {NO_TYPE_CHECK},", "no-type-check"),
]
TS_FORMS = [
    (BIOME_IGNORE, "biome-ignore"),
    (" biome-ignore lint/style/noNonNullAssertion: reason", "biome-ignore"),
    (TS_IGNORE, "ts-ignore"),
    (f"/** {TS}ignore */", "ts-ignore"),
    (f"/* {TS}ignore */", "ts-ignore"),
    (f" {TS}ignore */", "ts-ignore"),
    (f" / {TS}ignore */", "ts-ignore"),
    (f" * {TS}expect-error reason */", "ts-expect-error"),
    (TS_EXPECT, "ts-expect-error"),
    (f"f(); {TS_EXPECT}", "ts-expect-error"),
    (TS_NOCHECK, "ts-nocheck"),
    (f"{SLASHES} {TS.upper()}NOCHECK", "ts-nocheck"),
    (ESLINT, "eslint-disable"),
    (CAST, "as-unknown-as"),
    ("const x = (y as " + "unknown) as Z;", "as-unknown-as"),
    ("const x = <Z>(<" + "unknown>y);", "unknown-assertion"),
    ("const x = <Z><" + "unknown>y;", "unknown-assertion"),
]
# An Astro component: the TypeScript forms in its frontmatter, template and style,
# and the HTML comment form biome reads in the template.
ASTRO_FORMS = [
    *TS_FORMS,
    ("{/* biome-ignore lint/a11y/useAltText: reason */}", "biome-ignore"),
    ("<!-- biome-ignore lint/a11y/useAltText: reason -->", "biome-ignore"),
    ("<!--biome-ignore-all format: reason-->", "biome-ignore"),
]


class InlineSuppressionsTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.repo = GateRepo(Path(tmp))

    def rows(self) -> list[tuple[str, str, str]]:
        proc = self.repo.script("inline_suppressions.py")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rows = []
        for line in proc.stdout.splitlines():
            path, at, kind, size, message = line.split("\t", 4)
            self.assertEqual((size, message), ("-", "inline suppression"))
            text = lines((self.repo.root / path).read_text())[int(at) - 1]
            rows.append((path, kind, text.strip()))
        return rows

    def assert_forms(self, path: str, forms: list[tuple[str, str]]) -> None:
        self.repo.write(path, "".join(text + "\n" for text, _ in forms))
        self.assertEqual(self.rows(), [(path, kind, text.strip()) for text, kind in forms])

    def test_each_pattern_has_a_planted_form(self) -> None:
        planted = {
            "go": GO_FORMS,
            "python": PYTHON_FORMS,
            "typescript": TS_FORMS,
            "javascript": TS_FORMS,
            "astro": ASTRO_FORMS,
            "shell": [],
        }
        self.assertEqual(set(planted), set(KINDS))
        for language, forms in planted.items():
            for kind, pattern in KINDS[language]:
                texts = [text for text, planted_kind in forms if planted_kind == kind]
                self.assertTrue(any(pattern.search(t) for t in texts), f"{language} {kind}")

    def test_each_go_form_is_found_with_its_line(self) -> None:
        self.assert_forms("sdk/go/a.go", GO_FORMS)

    def test_each_python_form_is_found_with_its_line(self) -> None:
        self.assert_forms("sdk/python/b.py", PYTHON_FORMS)

    def test_each_typescript_form_is_found_with_its_line(self) -> None:
        self.assert_forms("sdk/ts/c.ts", TS_FORMS)

    def test_each_astro_form_is_found_with_its_line(self) -> None:
        self.assert_forms("website/src/components/A.astro", ASTRO_FORMS)

    def test_an_html_comment_is_a_form_only_in_astro(self) -> None:
        self.repo.write("website/src/a.ts", f"const s = 1; {ASTRO_FORMS[-2][0]}\n")
        self.repo.write("website/src/B.astro", "<!-- a comment that is not a suppression -->\n")
        self.assertEqual(self.rows(), [])

    def test_jscpd_markers_are_found_in_every_language_the_duplication_gate_reads(self) -> None:
        read = languages_read_by("duplication")
        self.assertEqual(languages_read_by("inline-suppressions"), read)
        self.assertIn("shell", read)
        paths = sorted(f"scripts/m{suffix}" for suffix, lang in LANGUAGES.items() if lang in read)
        for path in paths:
            self.repo.write(path, "".join(text + "\n" for text in JSCPD_FORMS))
        expected = [(path, "jscpd-ignore", text) for path in paths for text in JSCPD_FORMS]
        self.assertEqual(self.rows(), expected)

    def test_javascript_has_the_comment_forms_and_not_the_angle_bracket_cast(self) -> None:
        self.repo.write("scripts/d.mjs", "".join(text + "\n" for text, _ in TS_FORMS))
        kinds = {kind for _, kind, _ in self.rows()}
        self.assertEqual(kinds, {kind for _, kind in TS_FORMS} - {"unknown-assertion"})

    def test_a_form_the_tools_do_not_read_is_not_reported(self) -> None:
        ts = [
            f"/* * {TS}ignore */",
            "const p: Promise<" + "unknown> = f();",
            "const r = f<" + "unknown>(x);",
            "let a = b as unknown;",
            f" more text {TS}ignore */",
            f"{SLASHES} rome-ignore lint/suspicious/noDebugger: reason",
            "/* note biome-ignore lint/suspicious/noDebugger: reason */",
        ]
        python = [
            "def f() -> None:",
            "    return None",
            f"{HASH} {NO_TYPE_CHECK} named in a comment",
            f"names = ['{NO_TYPE_CHECK}']",
            f"run_{NO_TYPE_CHECK}_twice()",
            f"{HASH} {JSCPD.upper()}START",
            f"{HASH} {JSCPD.replace(':', ': ')}end",
        ]
        self.repo.write("sdk/ts/e.ts", "".join(line + "\n" for line in ts))
        self.repo.write("sdk/python/f.py", "".join(line + "\n" for line in python))
        self.repo.write("sdk/go/n.go", f"{SLASHES} lint:ignore U1000 reason\n")
        self.assertEqual(self.rows(), [])

    def test_a_comment_directive_inside_a_string_is_not_a_suppression(self) -> None:
        self.repo.write("scripts/gen.mjs", f'const header = "{TS_NOCHECK}\\n";\n')
        self.repo.write("sdk/python/d.py", f"text = '{NOQA}'\n")
        self.assertEqual(self.rows(), [])

    def test_a_marker_a_generator_writes_into_a_template_is_built_from_parts(self) -> None:
        generator = (GATES.parent / "sdk-types" / "gen_strict_validators.mjs").read_text()
        self.assertIn(SLASHES + ' ${"' + TS + '"}nocheck', generator)
        self.repo.write("scripts/sdk-types/gen_strict_validators.mjs", generator)
        self.assertEqual(self.rows(), [])
        whole = generator.replace('${"' + TS + '"}nocheck', TS + "nocheck")
        self.repo.write("scripts/sdk-types/gen_strict_validators.mjs", whole)
        self.assertEqual(
            self.rows(), [("scripts/sdk-types/gen_strict_validators.mjs", "ts-nocheck", TS_NOCHECK)]
        )

    def test_generated_files_are_not_read_and_the_site_is(self) -> None:
        generated = f"// Code generated by protoc-gen-go. DO NOT EDIT.\n\nvar x = 1 {NOLINT}\n"
        self.repo.write("gen/go/fora/gen.go", generated)
        hand = f'// Package a.\npackage a\n\nconst h = "Code generated"\n\nvar y = 1 {NOLINT}\n'
        self.repo.write("sdk/go/hand.go", hand)
        self.repo.write("website/e.ts", f"{TS_IGNORE}\n")
        self.repo.write("gen/ts/strict/f.ts", f"// Code generated. DO NOT EDIT.\n{TS_IGNORE}\n")
        self.repo.write("gen/ts/tests/g.ts", f"{TS_IGNORE}\n")
        self.repo.write(
            "schemas/h.go", f"// Package schemas.\npackage schemas\n\nvar z = 1 {NOLINT}\n"
        )
        self.assertEqual(
            self.rows(),
            [
                ("gen/ts/tests/g.ts", "ts-ignore", TS_IGNORE),
                ("schemas/h.go", "nolint", f"var z = 1 {NOLINT}"),
                ("sdk/go/hand.go", "nolint", f"var y = 1 {NOLINT}"),
                ("website/e.ts", "ts-ignore", TS_IGNORE),
            ],
        )

    def test_an_untracked_file_is_not_read(self) -> None:
        self.repo.write("sdk/h.py", f"x = 1  {NOQA}\n", stage=False)
        self.assertEqual(self.rows(), [])

    def test_a_number_in_the_line_is_part_of_its_identity(self) -> None:
        line = f"assert f(x) == (3 > 2)  {NOQA}"
        self.repo.write("sdk/python/g.py", line + "\n")
        self.assertEqual(self.rows(), [("sdk/python/g.py", "noqa", line)])


class ScannerThroughTheRatchetTest(unittest.TestCase):
    """inline_suppressions.py run by ratchet.py, as its gate runs it."""

    def setUp(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.repo = RatchetRepo(Path(tmp))

    def gate(self, command: str) -> tuple[int, str]:
        proc = self.repo.gate("inline-suppressions", command)
        return proc.returncode, proc.stdout + proc.stderr

    def test_a_new_suppression_fails_and_a_number_change_in_one_is_a_new_one(self) -> None:
        self.repo.write("sdk/python/g.py", f"x = f(3 > 2)  {NOQA}\n")
        self.assertEqual(self.gate("record")[0], 0)
        self.assertEqual(self.gate("check"), (0, ""))
        self.repo.write("sdk/python/g.py", f"x = f(4 > 2)  {NOQA}\n")
        code, out = self.gate("check")
        self.assertEqual(code, 1, out)
        self.assertIn("findings not in the baseline", out)
        self.assertIn("baseline entries that no longer occur", out)

    def test_a_jscpd_marker_in_a_shell_script_is_a_new_suppression(self) -> None:
        self.repo.write("scripts/a.sh", "echo a\n")
        self.assertEqual(self.gate("record")[0], 0)
        self.repo.write("scripts/a.sh", f"echo a  {HASH} {JSCPD}start\n")
        code, out = self.gate("check")
        self.assertEqual(code, 1, out)
        self.assertIn("findings not in the baseline", out)
        self.assertIn("scripts/a.sh: [jscpd-ignore]", out)


class SuppressionCarryTest(unittest.TestCase):
    """The gate with --base-ref: a suppression's entry never moves to another file.

    On main, sdk/ts/src/old.ts opens with a baselined file-wide suppression.
    """

    OLD = "sdk/ts/src/old.ts"

    def setUp(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.repo = RatchetRepo(Path(tmp))
        self.repo.write(self.OLD, f"{TS_NOCHECK}\nexport const a = 1;\nexport const b = 2;\n")
        self.assertEqual(self.gate("record").returncode, 0)
        self.repo.branch_off_main("introduce the gate")

    def gate(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.repo.gate("inline-suppressions", *args)

    def assert_new(self, path: str) -> None:
        """Assert that `record` and `check` with --base-ref refuse the suppression in `path`."""
        proc = self.gate("record", "--base-ref", "main")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("findings not in the baseline (fix them", proc.stdout)
        self.assertIn(f"{path}: [ts-nocheck]", proc.stdout)
        self.repo.write_entries(
            [
                {
                    "path": path,
                    "rule": "ts-nocheck",
                    "message": "inline suppression",
                    "source": TS_NOCHECK,
                    "count": 1,
                }
            ]
        )
        proc = self.gate("check", "--base-ref", "main")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("baseline entries added since main", proc.stdout)

    def test_a_suppression_removed_from_one_file_and_added_to_a_new_one_is_new(self) -> None:
        self.repo.write(self.OLD, "export const a = 1;\nexport const b = 2;\n")
        self.repo.write("sdk/ts/src/brand_new.ts", f"{TS_NOCHECK}\nexport function z(q) {{}}\n")
        self.assert_new("sdk/ts/src/brand_new.ts")

    def test_a_suppression_in_a_file_git_sees_as_a_copy_is_new(self) -> None:
        original = (self.repo.root / self.OLD).read_text()
        self.repo.write("sdk/ts/src/copy.ts", original + "export function z(q) {}\n")
        self.repo.write(self.OLD, "export const a = 1;\nexport const b = 2;\n")
        status = self.repo.git("diff", "--name-status", "-M", "-C", "main")
        self.assertIn("C", [s[0] for s in status.split()], status)
        self.assert_new("sdk/ts/src/copy.ts")

    def test_a_suppression_follows_its_renamed_file(self) -> None:
        self.repo.git("mv", self.OLD, "sdk/ts/src/renamed.ts")
        proc = self.gate("record", "--base-ref", "main")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("sdk/ts/src/renamed.ts: [ts-nocheck]", proc.stderr)
        proc = self.gate("check", "--base-ref", "main")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
