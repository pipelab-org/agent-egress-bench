#!/usr/bin/env python3
"""Regression tests for the validate-cases Make target's validator build."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]

# Stands in for `go build -o PATH .`: writes a validator that records the
# directory it runs from, or fails the build when FAKE_GO_FAIL is set.
FAKE_GO = """#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -z "${FAKE_GO_FAIL:-}" ] || exit 42
printf '#!/bin/sh\\ndirname "$0" >>"%s"\\n' "$RECORD" >"$out"
chmod +x "$out"
"""


def recipe() -> str:
    """Return the validate-cases recipe as the shell receives it from make."""
    source = (REPO / "Makefile").read_text(encoding="utf-8")
    body = source.split("\nvalidate-cases:\n", 1)[1].split("\n\n", 1)[0]
    lines = [line.removeprefix("\t").removeprefix("@") for line in body.split("\n")]
    return "\n".join(lines).replace("$$", "$")


class ValidateCasesTargetTest(unittest.TestCase):
    """Runs the extracted recipe with a stand-in Go toolchain."""

    def setUp(self) -> None:
        """Create a private TMPDIR, a fake `go` on PATH and a run record."""
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.tmpdir = root / "tmp"
        self.tmpdir.mkdir()
        bin_dir = root / "bin"
        bin_dir.mkdir()
        fake_go = bin_dir / "go"
        fake_go.write_text(FAKE_GO, encoding="utf-8")
        fake_go.chmod(0o755)
        self.record = root / "runs.txt"
        self.env = dict(
            os.environ,
            PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            RECORD=str(self.record),
            TMPDIR=str(self.tmpdir),
        )

    def tearDown(self) -> None:
        """Remove the private directory tree."""
        self.temp.cleanup()

    def run_recipe(self, tmpdir: str | None = None, **extra: str) -> subprocess.CompletedProcess[str]:
        """Run the recipe from the repository root with TMPDIR set as make would expand it."""
        value = str(self.tmpdir) if tmpdir is None else tmpdir
        absolute = os.path.normpath(os.path.join(REPO, value))
        script = recipe().replace("$(abspath $(TMPDIR))", absolute).replace("$(TMPDIR)", value)
        return subprocess.run(
            ["/bin/sh", "-c", script],
            cwd=REPO,
            env={**self.env, **extra},
            text=True,
            capture_output=True,
            timeout=60,
        )

    def test_failed_build_never_runs_a_leftover_validator(self) -> None:
        """A build failure stops before any validator runs."""
        stale = self.tmpdir / "aeb-validate"
        stale.write_text("#!/bin/sh\necho STALE_VALIDATOR_EXECUTED\nexit 0\n", encoding="utf-8")
        stale.chmod(0o755)
        result = self.run_recipe(FAKE_GO_FAIL="1")
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("STALE_VALIDATOR_EXECUTED", result.stdout)
        self.assertFalse(self.record.exists())
        self.assertEqual(sorted(p.name for p in self.tmpdir.iterdir()), ["aeb-validate"])

    def test_relative_tmpdir_builds_where_it_runs(self) -> None:
        """A relative TMPDIR still names one directory after the build changes into validate/."""
        relative = os.path.relpath(self.tmpdir, REPO)
        self.assertFalse(os.path.isabs(relative))
        result = self.run_recipe(tmpdir=relative)
        self.assertEqual(result.returncode, 0, result.stderr)
        dirs = self.record.read_text(encoding="utf-8").split()
        self.assertEqual(len(dirs), 1)
        self.assertEqual(Path(dirs[0]).parent, self.tmpdir)

    def test_each_run_builds_in_its_own_removed_directory(self) -> None:
        """Two runs use distinct build directories and remove both."""
        for _ in range(2):
            result = self.run_recipe()
            self.assertEqual(result.returncode, 0, result.stderr)
        dirs = self.record.read_text(encoding="utf-8").split()
        self.assertEqual(len(dirs), 2)
        self.assertNotEqual(dirs[0], dirs[1])
        for directory in dirs:
            self.assertEqual(Path(directory).parent, self.tmpdir)
            self.assertFalse(Path(directory).exists())


if __name__ == "__main__":
    unittest.main()
