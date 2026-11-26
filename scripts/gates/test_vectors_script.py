"""Tests for scripts/vectors.sh, the command that regenerates the conformance corpora.

Each test copies the script into a throwaway tree with a registry of two corpus files,
and puts a stub `go` first on PATH. The stub stands in for the Go emitters: on each
`go test` it writes the .got files the test's scenario calls for and exits as the
emitters would, and it logs every call, so a test can count the rounds.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import TYPE_CHECKING

from ratchet_harness import GateRepo

if TYPE_CHECKING:
    import subprocess

SCRIPT = Path(__file__).resolve().parents[1] / "vectors.sh"
CORPORA = ("sdk/go/a/testdata/a-vectors.json", "sdk/go/b/testdata/b-vectors.json")

# The stub `go`. It counts its calls in calls.log and reads its scenario from
# scenario.json: for call n (from 1), the .got files to write and the exit code.
# A call the scenario does not list writes nothing and exits 0. "drift" writes a
# different rendering of the first corpus on every call, as a non-deterministic
# emitter would.
STUB = """#!{python}
import json, pathlib, sys
root = pathlib.Path.cwd()
log = root / "calls.log"
n = len(log.read_text().splitlines()) + 1 if log.exists() else 1
log.write_text((log.read_text() if log.exists() else "") + " ".join(sys.argv[1:]) + "\\n")
scenario = json.loads((root / "scenario.json").read_text())
if scenario == "drift":
    (root / "{first}.got").write_text(f"rendering {{n}}\\n")
    sys.exit(1)
step = scenario.get(str(n), {{"gots": [], "exit": 0}})
for path in step["gots"]:
    (root / (path + ".got")).write_text(f"fresh {{path}}\\n")
sys.exit(step["exit"])
"""


class VectorsScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.repo = GateRepo(Path(tmp))
        self.root = self.repo.root
        shutil.copy2(SCRIPT, self.root / "scripts" / "vectors.sh")
        registry = {
            "corpora": {p: {"file": p, "list": "vectors", "row_key": "name"} for p in CORPORA}
        }
        self.repo.write("sdk/parity/corpora.json", json.dumps(registry))
        for path in CORPORA:
            self.repo.write(path, "stale\n")
        stub = self.root / "bin" / "go"
        stub.parent.mkdir()
        stub.write_text(STUB.format(python=sys.executable, first=CORPORA[0]))
        stub.chmod(0o755)
        self.path = f"{stub.parent}{os.pathsep}{os.environ['PATH']}"

    def run_script(self, scenario: object) -> subprocess.CompletedProcess[str]:
        (self.root / "scenario.json").write_text(json.dumps(scenario))
        return self.repo.run_command(
            ["bash", "scripts/vectors.sh"], env={"PATH": self.path}, timeout=60
        )

    def calls(self) -> int:
        return len((self.root / "calls.log").read_text().splitlines())

    def test_an_emitter_that_renders_something_new_every_run_stops_the_script(self) -> None:
        proc = self.run_script("drift")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("non-deterministic", proc.stderr)
        self.assertIn(f"{CORPORA[0]}.got", proc.stderr)
        # Two corpus files, so at most three rounds, and the last .got stays to compare.
        self.assertEqual(self.calls(), len(CORPORA) + 1)
        self.assertTrue((self.root / f"{CORPORA[0]}.got").exists())

    def test_an_emitter_that_stops_at_its_first_stale_corpus_takes_one_round_each(self) -> None:
        proc = self.run_script(
            {"1": {"gots": [CORPORA[0]], "exit": 1}, "2": {"gots": [CORPORA[1]], "exit": 1}}
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for path in CORPORA:
            self.assertEqual((self.root / path).read_text(), f"fresh {path}\n")
            self.assertFalse((self.root / f"{path}.got").exists())
        # Three rounds (the third clean), then the confirming run.
        self.assertEqual(self.calls(), 4)

    def test_a_failure_that_leaves_no_got_file_is_not_a_stale_corpus(self) -> None:
        proc = self.run_script({"1": {"gots": [], "exit": 1}, "2": {"gots": [], "exit": 1}})
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("without a stale corpus", proc.stderr)
        for path in CORPORA:
            self.assertEqual((self.root / path).read_text(), "stale\n")


if __name__ == "__main__":
    unittest.main()
