#!/usr/bin/env python3

import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.ci_scope import changed_paths, is_workflow_only


class CIScopeTest(unittest.TestCase):
    def test_review_source_policy_accepts_one_approved_pin_and_rejects_others(self) -> None:
        policy = runpy.run_path(str(Path(__file__).resolve().with_name("check_agent_review_workflow.py")))
        approved = policy["APPROVED_REVIEWER_SHAS"]
        prefix = "    uses: pipelab-org/agent-review/.github/workflows/agent-review-reusable.yaml@"
        cases = [("single", [approved[-1]], True), ("repeated", [approved[-1]] * 3, True),
                 ("mixed", [approved[0], approved[-1]], False), ("empty", [], False),
                 ("unapproved", ["0" * 40], False)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "review-caller-contract.yaml").write_text(policy["EXPECTED_CONTRACTS"][0], encoding="utf-8")
            for label, pins, accepted in cases:
                with self.subTest(label=label):
                    (workflows / "agent-review.yaml").write_text(
                        "".join(prefix + pin + " # main\n" for pin in pins), encoding="utf-8")
                    if accepted:
                        self.assertEqual(approved[-1], policy["validate_policy"](root))
                    else:
                        with self.assertRaises(ValueError):
                            policy["validate_policy"](root)

    def test_merge_queue_runs_required_workflows_and_uses_the_group_base(self) -> None:
        import os
        import re
        import yaml

        root = Path(__file__).resolve().parents[1]
        workflows = root / ".github/workflows"
        for name, required_jobs in [("validate.yaml", {"validate", "runner"}),
                                    ("security.yaml", {"codeql"}),
                                    ("pipelock.yaml", {"security-scan"})]:
            document = yaml.safe_load((workflows / name).read_text())
            triggers = document.get("on", document.get(True))
            self.assertEqual({"types": ["checks_requested"], "branches": ["main"]}, triggers["merge_group"])
            for job in required_jobs:
                self.assertNotIn("if", document["jobs"][job])
        document = yaml.safe_load((workflows / "validate.yaml").read_text())
        steps = document["jobs"]["validate"]["steps"]
        consumers = [("python3 scripts/ci_scope.py", "validation_base", "--base"),
                     ("python3 scripts/validate_gauntlet_records.py", "immutable_base", "--immutable-base")]
        for command, variable, flag in consumers:
            step = next(step for step in steps if command in step.get("run", ""))
            self.assertEqual("${{ github.event.merge_group.base_sha }}", step["env"]["MERGE_GROUP_BASE_SHA"])
            self.assertIn(f'{flag} "${variable}"', step["run"])
            selector = re.search(r"case .*?\nesac", step["run"], re.S).group()
            env = dict(os.environ, GITHUB_EVENT_NAME="merge_group", MERGE_GROUP_BASE_SHA="group-base", PR_BASE_SHA="wrong-pr-base", PUSH_BEFORE_SHA="wrong-push-base")
            result = subprocess.run(["bash", "-c", f'set -eu\n{selector}\nprintf "%s" "${variable}"'], env=env, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("group-base", result.stdout)
            env["GITHUB_EVENT_NAME"] = "unknown"
            result = subprocess.run(["bash", "-c", f'set -eu\n{selector}'], env=env, capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)

    def test_resolves_refs_before_diff_and_uses_nul_delimited_paths(self) -> None:
        completed = [
            subprocess.CompletedProcess([], 0, stdout="a" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="b" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=b".github/workflows/a.yaml\0scripts/line\nbreak.py\0", stderr=b""),
        ]
        with mock.patch("scripts.ci_scope.subprocess.run", side_effect=completed) as run:
            self.assertEqual(
                [".github/workflows/a.yaml", "scripts/line\nbreak.py"],
                changed_paths("--output=unsafe", "HEAD"),
            )

        self.assertEqual(
            ["git", "rev-parse", "--verify", "--end-of-options", "--output=unsafe^{commit}"],
            run.call_args_list[0].args[0],
        )
        diff_args = run.call_args_list[2].args[0]
        self.assertIn("-z", diff_args)
        self.assertEqual("--", diff_args[-1])

    def test_accepts_only_direct_workflow_yaml_files(self) -> None:
        self.assertTrue(is_workflow_only([".github/workflows/release.yaml", ".github/workflows/validate.yml"]))

    def test_rejects_empty_change(self) -> None:
        self.assertFalse(is_workflow_only([]))

    def test_rejects_any_non_workflow_path(self) -> None:
        self.assertFalse(is_workflow_only([".github/workflows/release.yaml", "scripts/release_build.py"]))

    def test_rejects_nested_or_non_yaml_workflow_paths(self) -> None:
        self.assertFalse(is_workflow_only([".github/workflows/archive/release.yaml"]))
        self.assertFalse(is_workflow_only([".github/workflows/README.md"]))

    def test_rejects_path_escape(self) -> None:
        self.assertFalse(is_workflow_only([".github/workflows/../release.yaml"]))

    def test_non_workflow_deletion_cannot_hide_behind_workflow_edit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            workflow = repo / ".github/workflows/validate.yaml"
            source = repo / "scripts/helper.py"
            workflow.parent.mkdir(parents=True)
            source.parent.mkdir()
            workflow.write_text("name: before\n", encoding="utf-8")
            source.write_text("print('before')\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=repo, check=True)
            base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, text=True, capture_output=True).stdout.strip()
            workflow.write_text("name: after\n", encoding="utf-8")
            source.unlink()
            subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "change"], cwd=repo, check=True)

            original = Path.cwd()
            try:
                import os

                os.chdir(repo)
                paths = changed_paths(base, "HEAD")
            finally:
                os.chdir(original)
            self.assertEqual({".github/workflows/validate.yaml", "scripts/helper.py"}, set(paths))
            self.assertFalse(is_workflow_only(paths))


if __name__ == "__main__":
    unittest.main()
