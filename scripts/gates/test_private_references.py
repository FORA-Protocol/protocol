"""Tests for private_references.py, run through its command line.

Each test copies the gate modules into a throwaway git repository, writes and
stages files, and reads the rows the script prints. Every reference is
assembled from parts, so this file holds none of its own.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest

from ratchet_harness import GATES, ScannerTestCase

SCANNER = "private_references.py"
KEY = "FOR" + "A-84"
EMPTY_ALLOWED = "ALLOWED: tuple[Allowed, ...] = ()"

# One line per form, with the kind the scanner reports it as.
FORMS = [
    (f"tracked as {KEY}", "tracker-key"),
    ("filed in Ji" + "ra", "tracker"),
    ("https://example.atlass" + "ian.net/browse/X", "tracker"),
    ("run bd show from the Be" + "ads tracker", "tracker"),
    ("cat .be" + "ads/issues.jsonl", "tracker"),
    ("the unset-kind half (for" + "a-4c7)", "task-id"),
    ("child task for" + "a-4c7.2", "task-id"),
    ("see agentic-content-" + "access-un015", "private-repository"),
    ("derived in pi" + "arch", "private-repository"),
    ("the pi-" + "terraform stack", "private-repository"),
    ("open /" + "Users/dev/notes.txt", "local-path"),
    ("`/" + "home/dev/x`", "local-path"),
    ("file://" + "/Us" + "ers/dev/x", "local-path"),
    ("C:\\" + "Users\\dev\\x", "local-path"),
    ("cd ~/" + "projects/protocol", "local-path"),
    ("the worker (src/" + "edge/src/verify.ts)", "service-path"),
    ("the shim in src/" + "mcp/shim.py", "service-path"),
    ("src/" + "exchange/internal/signing", "service-path"),
    ("ported from internal/" + "somepkg/x.go", "service-path"),
    ("ported from ./internal/" + "somepkg", "service-path"),
    ("the edge tests in src/" + "edge/test/app.test.ts", "service-path"),
    ("run ./src/" + "broker/main.go", "service-path"),
]

# Spellings that hide a reference from a plain match, with the kind still reported.
EVASIONS = [
    ("in any case: For" + "a-123", "tracker-key"),
    ("joined to a word: fix_FOR" + "A-123", "tracker-key"),
    ("an HTML reference: FOR" + "A&#45;123", "tracker-key"),
    ("a non-breaking hyphen: FOR" + "A\u2011123", "tracker-key"),
    ("a zero-width space: FO\u200b" + "RA-123", "tracker-key"),
    ("emphasis inside: FO**" + "RA-123", "tracker-key"),
    ("an escaped hyphen: FOR" + "A\\-123", "tracker-key"),
    ("in any case: Agentic-Content-" + "Access", "private-repository"),
    ("snake case: agentic_content_" + "access", "private-repository"),
    ("camel case: agenticContent" + "Access", "private-repository"),
    ("the superuser's home: /" + "root/projects/notes.txt", "local-path"),
    ("a superuser dot-file: /" + "root/.ssh/id_ed25519", "local-path"),
    ("in upper case: FOR" + "A-4C7", "task-id"),
    ("the home variable: $" + "HOME/projects/protocol", "local-path"),
    ("in lower case: /" + "users/dev/x", "local-path"),
    ("a named home: ~" + "dev/notes", "local-path"),
    ("a macOS temporary directory: /private/var/" + "folders/ab/T/x", "local-path"),
    ('p := "/' + 'Users/alice/projects/x"', "local-path"),
    ("p = '/" + "Users/alice/projects/x'", "local-path"),
    ('{"path": "/' + 'home/alice/work"}', "local-path"),
    ('"/' + 'root/projects/x"', "local-path"),
    ("GOPATH=/" + "root/go/src/x", "local-path"),
    ("built in /" + "root/fora/x", "local-path"),
    ("GET /" + "Users/alice/projects/x", "local-path"),
    ("#/" + "Users/alice/x", "local-path"),
    ("cd /" + "Users/alice", "local-path"),
    ("/" + "home/alice is the dir", "local-path"),
]

# Lines that look close to a reference and are not one.
CLEAN = [
    "https://github.com/org/repo/blob/main/src/" + "edge/src/verify.ts",
    "https://example.com/" + "home/dev",
    "the FORA-" + "Protocol organization, ADR-013 and RFC-7638",
    "sdk/go/internal/" + "vectorio holds the reader",
    "internal/" + "vectorio is this SDK's package",
    "cd src/" + "edge, then run the build",
    "my-src/" + "edge/x and x-internal/" + "somepkg",
    "the for" + "a-c2pa-v1 profile and the for" + "a-exchange image",
    "state in ~/" + ".fora/budget.json",
    "key.replace(/~/" + 'g, "~0")',
    "tool state in $" + "HOME/.fora/budget.json",
    "a snake_case name, a FORA_" + "VERSION and a fora_" + "sdk module",
    "GET /" + "users/me/settings returns the caller's settings",
    "the endpoint /" + "users/me returns the caller",
    '"pointer": "/' + 'root/child/name" and #/' + "root/child/name",
    "x & ~" + "mask/2 and y ~" + "mask/2",
]


class PrivateReferencesTest(ScannerTestCase):
    scanner = SCANNER
    message = "private reference"
    gate_name = "private-references"

    def setUp(self) -> None:
        super().setUp()
        self.repo.write("sdk/go/internal/vectorio/vectorio.go", "package vectorio\n")

    def allow(self, *entries: str) -> None:
        """Rewrite the copy of the scanner with `entries` (Allowed(...) source) as ALLOWED."""
        text = (GATES / SCANNER).read_text()
        self.assertIn(EMPTY_ALLOWED, text)
        allowed = "ALLOWED: tuple[Allowed, ...] = (" + "".join(e + ", " for e in entries) + ")"
        self.repo.write(
            f"scripts/gates/{SCANNER}", text.replace(EMPTY_ALLOWED, allowed), stage=False
        )

    def test_each_form_is_found_with_its_kind_and_line(self) -> None:
        self.repo.write("docs/notes.md", "".join(f"  {text}\n" for text, _ in FORMS))
        self.assertEqual(
            self.named_lines(), [("docs/notes.md", kind, text) for text, kind in FORMS]
        )

    def test_a_hidden_spelling_is_still_found(self) -> None:
        self.repo.write("docs/hidden.md", "".join(f"{text}\n" for text, _ in EVASIONS))
        self.assertEqual(
            self.named_lines(), [("docs/hidden.md", kind, text) for text, kind in EVASIONS]
        )

    def test_a_key_split_across_a_line_break_is_found_on_its_first_line(self) -> None:
        self.repo.write("docs/split.md", "intro\nsee FOR" + "A-\n84 for the details\n")
        self.assertEqual(
            self.scanned(), [("docs/split.md", "2", "tracker-key", "-", "private reference")]
        )

    def test_a_key_split_across_two_comment_lines_is_found(self) -> None:
        pairs = [
            "// see FOR" + "A-\n// 84 for details",
            "# see FOR" + "A-\n# 84",
            " * see FOR" + "A-\n * 84",
            "-- see FOR" + "A-\n-- 84",
        ]
        self.repo.write("docs/comments.txt", "\n".join(pairs) + "\n")
        rows = [(line, kind) for _, line, kind, _, _ in self.scanned()]
        self.assertEqual(
            rows,
            [
                ("1", "tracker-key"),
                ("3", "tracker-key"),
                ("5", "tracker-key"),
                ("7", "tracker-key"),
            ],
        )

    def test_a_word_and_a_minus_on_the_next_line_are_not_joined(self) -> None:
        self.repo.write(
            "docs/prose.md", "the protocol is called FOR" + "A\n-1 point on the scale\n"
        )
        self.assertEqual(self.scanned(), [])

    def test_a_tracked_path_is_read_too(self) -> None:
        self.repo.write(f"docs/{KEY}-notes.md", "clean\n")
        self.assertEqual(
            self.scanned(),
            [(f"docs/{KEY}-notes.md", "-", "tracker-key", "-", "private reference in the path")],
        )

    def test_utf16_text_with_a_byte_order_mark_is_read(self) -> None:
        (self.repo.root / "docs").mkdir()
        (self.repo.root / "docs/wide.txt").write_bytes(f"\ufeffsee {KEY}\n".encode("utf-16-le"))
        self.repo.git("add", "docs/wide.txt")
        self.assertEqual(
            self.scanned(), [("docs/wide.txt", "1", "tracker-key", "-", "private reference")]
        )

    def test_a_line_close_to_a_reference_is_not_one(self) -> None:
        self.repo.write("docs/clean.md", "".join(line + "\n" for line in CLEAN))
        self.assertEqual(self.named_lines(), [])

    def test_every_tracked_text_file_is_read_whatever_its_scope(self) -> None:
        line = f"see {KEY}"
        paths = [
            "website/src/a.test.mjs",
            "gen/go/fora/v1/x.go",
            "sdk/parity/symbol-map.json",
            "README",
        ]
        for path in paths:
            self.repo.write(path, f"// Code generated. DO NOT EDIT.\n{line}\n")
        self.assertEqual(self.named_lines(), [(p, "tracker-key", line) for p in sorted(paths)])

    def test_a_row_names_its_line_counted_at_each_newline(self) -> None:
        # A form feed and a lone carriage return end no line for the ratchet.
        self.repo.write("docs/a.md", f"one\x0ctwo\rthree\nsee {KEY}\n")
        self.assertEqual(
            self.scanned(), [("docs/a.md", "2", "tracker-key", "-", "private reference")]
        )

    def test_untracked_and_binary_files_are_not_read(self) -> None:
        self.repo.write("docs/draft.md", f"{KEY}\n", stage=False)
        (self.repo.root / "logo.png").write_bytes(b"\x89PNG\0" + KEY.encode())
        self.repo.git("add", "logo.png")
        self.assertEqual(self.named_lines(), [])

    def test_an_allowed_line_passes_only_in_its_own_file(self) -> None:
        line = f"see {KEY}"
        self.repo.write("docs/a.md", line + "\n")
        self.repo.write("docs/b.md", line + "\n")
        self.allow('Allowed("docs/a.md", "tracker-key", "see FOR" + "A-84", "a quoted record")')
        self.assertEqual(self.named_lines(), [("docs/b.md", "tracker-key", line)])

    def test_an_allowance_that_matches_nothing_is_reported(self) -> None:
        self.allow('Allowed("docs/a.md", "tracker-key", "see FOR" + "A-84", "a quoted record")')
        self.assertEqual(
            self.scanned(), [("docs/a.md", "-", "stale-allowance", "-", f"tracker-key: see {KEY}")]
        )


class ScannerThroughTheRatchetTest(ScannerTestCase):
    """private_references.py run by ratchet.py, as its gate runs it."""

    scanner = SCANNER
    gate_name = "private-references"

    def test_the_empty_baseline_passes_and_a_new_reference_fails(self) -> None:
        self.repo.write("docs/a.md", "clean\n")
        self.assertEqual(self.gate("record")[0], 0)
        self.assertEqual(self.repo.entries(), [])
        self.assertEqual(self.gate("check"), (0, ""))
        self.repo.write("docs/a.md", f"tracked as {KEY}\n")
        code, out = self.gate("check")
        self.assertEqual(code, 1, out)
        self.assertIn("findings not in the baseline", out)
        self.assertIn(KEY, out)


if __name__ == "__main__":
    unittest.main()
