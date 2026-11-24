"""The test case for a scanner of this directory, run in a throwaway repository."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from ratchet_harness import RatchetRepo
from scope import lines


class ScannerTestCase(unittest.TestCase):
    """A test case for one scanner of this directory, named by `scanner`.

    `self.repo` is a fresh RatchetRepo holding a copy of the scanner, and `gate`
    runs a copy of the scanner's gate script, named by `gate_name`.
    """

    scanner = ""
    # The message of a row that names a line, for a scanner whose rows all carry one.
    message = ""
    # The scanner's gate, by the name in scripts/gates/gate-<name>.sh.
    gate_name = ""

    def setUp(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.repo = RatchetRepo(Path(tmp))
        self.repo.copy(self.scanner)

    def scanned(self) -> list[tuple[str, str, str, str, str]]:
        """Run the scanner from the root; return its (path, line, rule, size, message) rows."""
        proc = self.repo.script(self.scanner)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rows = []
        for row in proc.stdout.splitlines():
            path, at, rule, size, message = row.split("\t", 4)
            rows.append((path, at, rule, size, message))
        return rows

    def file_rows(self) -> list[tuple[str, str, str, str]]:
        """Return the (path, rule, size, message) rows, each about a whole file."""
        rows = self.scanned()
        self.assertEqual([at for _, at, *_ in rows], ["-"] * len(rows), "whole-file rows")
        return [(path, rule, size, message) for path, _, rule, size, message in rows]

    def named_lines(self) -> list[tuple[str, str, str]]:
        """Return (path, rule, the named line's stripped text) for each row.

        Each row must name a line, measure nothing and carry `message`. Lines are
        counted at each newline, as the ratchet counts them.
        """
        rows = []
        for path, at, rule, size, message in self.scanned():
            self.assertEqual((size, message), ("-", self.message))
            text = lines((self.repo.root / path).read_text())[int(at) - 1]
            rows.append((path, rule, text.strip()))
        return rows

    def gate(self, command: str) -> tuple[int, str]:
        """Run the scanner's gate script with `command`; return its exit code and output."""
        proc = self.repo.gate(self.gate_name, command)
        return proc.returncode, proc.stdout + proc.stderr
