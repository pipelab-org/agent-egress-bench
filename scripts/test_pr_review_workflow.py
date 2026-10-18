#!/usr/bin/env python3
"""Validate bounded proposed workflows using trusted default-branch definitions."""

import hashlib
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows/pr-review.yaml"
MAX_WORKFLOW_BYTES = 65536
# Upgrade trusted approvals in three stages: expand, migrate, then contract.
# Both bootstrap and trusted validation must pass each stage before merging.
APPROVED_REVIEWER_SHAS = ("4edcf46d02011c2aa1e305aff69d4d7100aae0ca",)
EXPECTED_CALLERS = (r"""name: AI PR Review

on:
  issue_comment:
    types: [created]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  review:
    if: >-
      github.actor == 'luckyPipewrench' &&
      github.actor_id == '142104046' &&
      github.run_attempt == '1' &&
      github.triggering_actor == 'luckyPipewrench' &&
      github.event.comment.user.login == 'luckyPipewrench' &&
      github.event.comment.user.id == 142104046 &&
      github.event.comment.author_association == 'MEMBER' &&
      github.event.issue.pull_request &&
      (github.event.comment.body == '/review' ||
       github.event.comment.body == '/review deep')
    # Keep both pins equal until the nested source identity is verified live.
    uses: pipelab-org/pipelock/.github/workflows/pr-review-reusable.yaml@REVIEWER_SHA
    with:
      reviewer_sha: REVIEWER_SHA
      pr_number: ${{ github.event.issue.number }}
      review_mode: >-
        ${{ github.event.comment.body == '/review deep' && 'deep' ||
        'default' }}
    secrets:
      review_token: ${{ secrets.GITHUB_TOKEN }}
      openai_api_key: ${{ secrets.OPENAI_API_KEY }}
""",)
EXPECTED_CONTRACTS = (r"""name: Review caller contract

on:
  pull_request:
    types: [opened, synchronize, reopened]
    paths:
      - '.github/workflows/pr-review.yaml'
      - '.github/workflows/review-caller-contract.yaml'
      - 'scripts/test_pr_review_workflow.py'
  pull_request_target:
    types: [opened, synchronize, reopened]
    paths:
      - '.github/workflows/pr-review.yaml'
      - '.github/workflows/review-caller-contract.yaml'
      - 'scripts/test_pr_review_workflow.py'
  push:
    branches: [main]
    paths:
      - '.github/workflows/pr-review.yaml'
      - '.github/workflows/review-caller-contract.yaml'
      - 'scripts/test_pr_review_workflow.py'

permissions:
  contents: read

jobs:
  bootstrap:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Check out proposed contract for unprivileged installation tests
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          persist-credentials: false
      - name: Test proposed caller and contract without provider secrets
        run: python3 -I scripts/test_pr_review_workflow.py
  contract:
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Check out trusted default-branch caller validator
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          repository: luckyPipewrench/agent-egress-bench
          ref: ${{ github.sha }}
          path: trusted-validator
          persist-credentials: false
          sparse-checkout: scripts/test_pr_review_workflow.py
          sparse-checkout-cone-mode: false
      - name: Check out proposed caller as data
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name || github.repository }}
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
          # Proposed workflows are bounded data; no proposed code is executed.
          allow-unsafe-pr-checkout: true
          path: proposed
          persist-credentials: false
          filter: blob:none
          sparse-checkout: |
            .github/workflows/pr-review.yaml
            .github/workflows/review-caller-contract.yaml
          sparse-checkout-cone-mode: false
      - name: Validate proposed caller with trusted test code
        id: validate
        run: |
          python3 -I - <<'PY'
          import importlib.util
          import os
          import pathlib
          import unittest

          validator = pathlib.Path("trusted-validator/scripts/test_pr_review_workflow.py")
          spec = importlib.util.spec_from_file_location("trusted_caller", validator)
          module = importlib.util.module_from_spec(spec)
          spec.loader.exec_module(module)
          module.WORKFLOW = pathlib.Path("proposed/.github/workflows/pr-review.yaml")
          reviewer_sha = module.validate_caller(module.WORKFLOW)
          module.validate_contract(
              pathlib.Path("proposed/.github/workflows/review-caller-contract.yaml")
          )
          suite = unittest.defaultTestLoader.loadTestsFromModule(module)
          result = unittest.TextTestRunner(verbosity=2).run(suite)
          if not result.wasSuccessful():
              raise SystemExit(1)
          with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
              output.write(f"reviewer_sha={reviewer_sha}\n")
          PY
      - name: Check out immutable reviewer and its security tests
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          repository: luckyPipewrench/pipelock
          ref: ${{ steps.validate.outputs.reviewer_sha }}
          path: trusted-reviewer
          persist-credentials: false
      - name: Install pinned reviewer test dependencies
        working-directory: trusted-reviewer
        run: |
          python3 -m venv .review-test-venv
          .review-test-venv/bin/python -m pip install --require-hashes \
            -r .github/actions/pr-review/requirements.txt \
            -r .github/requirements-pr-review-test.txt
      - name: Verify shared reviewer workflow protections
        working-directory: trusted-reviewer
        run: >-
          .review-test-venv/bin/python -m unittest
          scripts.pr_review_test.WorkflowPackagingTest
          scripts.pr_review_test.FailureDirectionTest.test_review_job_timeout_exceeds_the_wall_clock_with_finalization_margin
""",)



# These digests approve the complete shared-review installation as one state.
# They bind repository data and executable validation to the reviewed migration.
SHARED_FILES = {'.github/workflows/agent-review.yaml': '644f8a65d0dad6ff62d2502f48650b7a94fb6ae97afad65f96fda042c584caea', '.github/agent-review.toml': 'bf12e8fb77baa1840c5d167c432fde1c03298ed311cb45635374cb40e1a8ba02', '.github/workflows/review-caller-contract.yaml': 'd304bf0150b7f48dac125f4e697a6c9f3798298f616e1b230707dc9ec9b43895', 'scripts/check_agent_review_workflow.py': '969a0930c2aa64e1eff3782144c08646de4f16bd060e8d48ee54ad10a20255ae'}
MIGRATED_WORKFLOWS = ('.github/workflows/agent-review.yaml', '.github/workflows/continuous-gauntlet.yaml', '.github/workflows/dependency-review.yaml', '.github/workflows/pipelock.yaml', '.github/workflows/publish-release.yaml', '.github/workflows/release.yaml', '.github/workflows/review-caller-contract.yaml', '.github/workflows/scorecard.yaml', '.github/workflows/security.yaml', '.github/workflows/validate.yaml')


def git_output(root, *arguments):
    """Read repository objects without checking out or executing proposed files."""
    return subprocess.check_output(
        ["git", "-C", str(root), *arguments], stderr=subprocess.PIPE,
    )


def tree_entries(root, *paths):
    entries = {}
    for record in git_output(root, "ls-tree", "-z", "HEAD", "--", *paths).split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        entries[name.decode("utf-8")] = (mode, kind, oid.decode("ascii"))
    return entries


def read_blob(root, entry):
    """Bound object reads and verify bytes against their Git object identity."""
    mode, kind, oid = entry
    if mode != b"100644" or kind != b"blob":
        raise ValueError("shared review files must be regular non-executable blobs")
    size = int(git_output(root, "cat-file", "-s", oid))
    if size < 0 or size > MAX_WORKFLOW_BYTES:
        raise ValueError("shared review blob exceeds the data limit")
    data = git_output(root, "cat-file", "blob", oid)
    if len(data) != size:
        raise ValueError("shared review blob size differs from its object header")
    header = b"blob " + str(size).encode("ascii") + b"\0"
    if hashlib.sha1(header + data).hexdigest() != oid:
        raise ValueError("shared review blob differs from its Git identity")
    return data


def shared_migration(path):
    """Admit only complete approved migrations; retain legacy suite selection."""
    path = pathlib.Path(path).absolute()
    if path.parent.name != "workflows" or path.parent.parent.name != ".github":
        return False
    root = path.parents[2]
    if not (root / ".git").exists():
        return False
    old = ".github/workflows/pr-review.yaml"
    entries = tree_entries(root, old, *SHARED_FILES)
    shared = set(entries).intersection(SHARED_FILES)
    contract = ".github/workflows/review-caller-contract.yaml"
    if old in entries:
        if shared - {contract}:
            raise ValueError("legacy and shared review installations must not mix")
        if contract not in entries or read_blob(root, entries[contract]).decode("utf-8") not in EXPECTED_CONTRACTS:
            raise ValueError("legacy caller requires its legacy checking workflow")
        return False
    if shared != set(SHARED_FILES):
        raise ValueError("shared review installation is incomplete")
    inventory = tree_entries(root, ".github/workflows/")
    if set(inventory) != set(MIGRATED_WORKFLOWS):
        raise ValueError("migration changes unexpected workflow paths")
    for name, expected in SHARED_FILES.items():
        if hashlib.sha256(read_blob(root, entries[name])).hexdigest() != expected:
            raise ValueError("shared review installation differs from its approved data")
    return True


def read_workflow(path):
    """Read bounded UTF-8 data without following any path-component symlink."""
    path = pathlib.Path(path)
    if ".." in path.parts:
        raise ValueError("workflow path must not traverse parents")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.anchor if path.is_absolute() else ".", directory_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_WORKFLOW_BYTES:
                raise ValueError("workflow must be a bounded regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(MAX_WORKFLOW_BYTES + 1)
            if len(data) > MAX_WORKFLOW_BYTES:
                raise ValueError("workflow exceeds the data limit")
            return data.decode("utf-8")
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def validate_caller(path):
    """Accept only an approved shape with matching approved immutable pins."""
    if shared_migration(path):
        return APPROVED_REVIEWER_SHAS[0]
    text = read_workflow(path)
    pins = re.findall(
        r"(?:pr-review-reusable\.yaml@|reviewer_sha: )([0-9a-f]{40})$",
        text, re.MULTILINE,
    )
    if len(pins) != 2 or pins[0] != pins[1]:
        raise ValueError("both reviewer references must be matching full SHAs")
    if pins[0] not in APPROVED_REVIEWER_SHAS:
        raise ValueError("land reviewer approval on main before migrating the caller")
    if text.replace(pins[0], "REVIEWER_SHA") not in EXPECTED_CALLERS:
        raise ValueError("proposed caller differs from its trusted definition")
    return pins[0]


def validate_contract(path):
    """Compare exact text, including executable block-scalar comments."""
    if shared_migration(path):
        return
    if read_workflow(path) not in EXPECTED_CONTRACTS:
        raise ValueError("proposed contract differs from its trusted definition")


class ReviewCallerTest(unittest.TestCase):
    def test_caller_contract_and_matching_immutable_pins(self):
        validate_caller(WORKFLOW)

    def test_installed_contract(self):
        validate_contract(WORKFLOW.with_name("review-caller-contract.yaml"))

    def test_only_the_organization_caller_and_reviewer_are_approved(self):
        self.assertEqual(APPROVED_REVIEWER_SHAS, ("4edcf46d02011c2aa1e305aff69d4d7100aae0ca",))
        self.assertEqual(len(EXPECTED_CALLERS), 1)
        self.assertEqual(len(EXPECTED_CONTRACTS), 1)
        for required in [
            "uses: pipelab-org/pipelock/.github/workflows/pr-review-reusable.yaml@REVIEWER_SHA",
            "github.actor_id == '142104046'",
            "github.event.comment.user.id == 142104046",
            "github.run_attempt == '1'",
            "author_association == 'MEMBER'",
        ]:
            self.assertIn(required, EXPECTED_CALLERS[0])
        self.assertNotIn("luckyPipewrench/pipelock/", EXPECTED_CALLERS[0])


class WorkflowInputTest(unittest.TestCase):
    def test_bounded_regular_utf8_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "caller.yaml"
            path.write_text("name: caller\n", encoding="utf-8")
            self.assertEqual(read_workflow(path), "name: caller\n")
            path.write_bytes(b"x" * (MAX_WORKFLOW_BYTES + 1))
            with self.assertRaises(ValueError):
                read_workflow(path)
            path.write_bytes(b"\xff")
            with self.assertRaises(UnicodeError):
                read_workflow(path)

    def test_file_growth_after_stat_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "caller.yaml"
            path.write_text("name: caller\n", encoding="utf-8")
            original_fstat = os.fstat

            def grow_after_stat(fd):
                info = original_fstat(fd)
                path.write_bytes(b"x" * (MAX_WORKFLOW_BYTES + 1))
                return info

            with mock.patch.object(os, "fstat", side_effect=grow_after_stat):
                with self.assertRaisesRegex(ValueError, "exceeds the data limit"):
                    read_workflow(path)

    def test_symlink_and_symlink_parent_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            directory = root / "outside"
            directory.mkdir()
            path = directory / "caller.yaml"
            path.write_text("outside sentinel", encoding="utf-8")
            link = root / "caller.yaml"
            link.symlink_to(path)
            parent = root / "proposed"
            parent.symlink_to(directory, target_is_directory=True)
            for candidate in [link, parent / "caller.yaml"]:
                with self.subTest(path=candidate), self.assertRaises(OSError):
                    read_workflow(candidate)

    def test_fifo_and_parent_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "caller.yaml"
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                read_workflow(path)
            with self.assertRaises(ValueError):
                read_workflow(path.parent / ".." / "caller.yaml")


    def test_exact_contract_and_caller_changes_are_rejected(self):
        caller = EXPECTED_CALLERS[0].replace("REVIEWER_SHA", APPROVED_REVIEWER_SHAS[0])
        contract = EXPECTED_CONTRACTS[0]
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "workflow.yaml"
            for expected, check, mutations in [
                (caller, validate_caller, [
                    caller.replace("contents: read", "contents: write"),
                    caller + "# unapproved caller comment\n",
                    caller.replace("  issue_comment:", "  issue_comment:\n\n"),
                    caller.replace(APPROVED_REVIEWER_SHAS[0], "main"),
                    caller.replace(APPROVED_REVIEWER_SHAS[0], "a" * 40, 1),
                    caller.replace(APPROVED_REVIEWER_SHAS[0], "a" * 40),
                    caller.replace(APPROVED_REVIEWER_SHAS[0], "a" * 39),
                    caller.replace(APPROVED_REVIEWER_SHAS[0], "3e8534e0dd621c62879238cc01d56f7e58e9d096"),
                    caller.replace("pipelab-org/pipelock/", "luckyPipewrench/pipelock/"),
                    caller.replace("github.actor_id == '142104046'", "github.actor_id == '0'"),
                    caller.replace("github.event.comment.user.id == 142104046", "github.event.comment.user.id == 0"),
                    caller.replace("github.run_attempt == '1'", "github.run_attempt == '2'"),
                    caller.replace("author_association == 'MEMBER'", "author_association == 'OWNER'"),
                ]),
                (contract, validate_contract, [
                    contract.replace("contents: read", "contents: write"),
                    contract.replace("module.validate_contract(", "module.skip_contract("),
                    contract.replace("--require-hashes", "--no-deps"),
                    contract.replace("WorkflowPackagingTest", "MissingProtectionTest"),
                    contract.replace("ref: ${{ github.sha }}", "ref: ${{ github.event.pull_request.head.sha }}"),
                    contract.replace("          scripts.pr_review_test.FailureDirectionTest", "          # retained\n          scripts.pr_review_test.FailureDirectionTest"),
                    contract.replace("ref: ${{ steps.validate.outputs.reviewer_sha }}", "ref: main"),
                    contract + "\n",
                ]),
            ]:
                path.write_text(expected, encoding="utf-8")
                check(path)
                for mutation in mutations:
                    with self.subTest(check=check.__name__, mutation=mutation[:60]):
                        self.assertNotEqual(mutation, expected)
                        path.write_text(mutation, encoding="utf-8")
                        with self.assertRaises(ValueError):
                            check(path)

    def test_reviewer_upgrade_expand_migrate_contract(self):
        """Trusted code expands approval before migration and removes it after."""
        old = APPROVED_REVIEWER_SHAS[0]
        new = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            caller = pathlib.Path(tmp) / "caller.yaml"
            contract = pathlib.Path(tmp) / "contract.yaml"
            contract.write_text(EXPECTED_CONTRACTS[0], encoding="utf-8")
            for approved, proposed, accepted in [
                ((old,), old, True),
                ((old,), new, False),
                ((old, new), old, True),
                ((old, new), new, True),
                ((new,), new, True),
                ((new,), old, False),
            ]:
                with self.subTest(approved=approved, proposed=proposed):
                    caller.write_text(EXPECTED_CALLERS[0].replace("REVIEWER_SHA", proposed), encoding="utf-8")
                    with mock.patch.dict(globals(), APPROVED_REVIEWER_SHAS=approved):
                        if accepted:
                            self.assertEqual(validate_caller(caller), proposed)
                            validate_contract(contract)
                        else:
                            with self.assertRaises(ValueError):
                                validate_caller(caller)

    def test_shape_upgrade_expand_migrate_contract(self):
        """Future exact templates can migrate without weakening the comparator."""
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "workflow.yaml"
            for key, check, old in [
                ("EXPECTED_CALLERS", validate_caller, EXPECTED_CALLERS[0]),
                ("EXPECTED_CONTRACTS", validate_contract, EXPECTED_CONTRACTS[0]),
            ]:
                new = old.replace("name:", "# approved shape revision\nname:", 1)
                for approved, proposed, accepted in [
                    ((old,), old, True), ((old,), new, False),
                    ((old, new), old, True), ((old, new), new, True),
                    ((new,), new, True), ((new,), old, False),
                ]:
                    with self.subTest(key=key, accepted=accepted):
                        path.write_text(proposed.replace("REVIEWER_SHA", APPROVED_REVIEWER_SHAS[0]), encoding="utf-8")
                        with mock.patch.dict(globals(), {key: approved}):
                            if accepted:
                                check(path)
                            else:
                                with self.assertRaises(ValueError):
                                    check(path)



class SharedMigrationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.git("init", "-q")
        self.caller = self.root / ".github/workflows/pr-review.yaml"
        self.contract = self.caller.with_name("review-caller-contract.yaml")
        self.shared_data = {name: ("approved " + name + "\n").encode() for name in SHARED_FILES}
        self.digests = {name: hashlib.sha256(data).hexdigest() for name, data in self.shared_data.items()}
        self.patch = mock.patch.dict(globals(), SHARED_FILES=self.digests)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        for name in MIGRATED_WORKFLOWS:
            if name not in self.shared_data:
                self.write(name, b"name: existing CI\n")

    def git(self, *arguments):
        return subprocess.check_output(
            ["git", "-C", str(self.root), "-c", "user.name=Test",
             "-c", "user.email=test@example.invalid", *arguments], stderr=subprocess.PIPE,
        )

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-qm", "test fixture")

    def migrate(self):
        for name, data in self.shared_data.items():
            self.write(name, data)
        self.commit()

    def legacy(self):
        self.write(".github/workflows/pr-review.yaml",
                   EXPECTED_CALLERS[0].replace("REVIEWER_SHA", APPROVED_REVIEWER_SHAS[0]).encode())
        self.write(".github/workflows/review-caller-contract.yaml", EXPECTED_CONTRACTS[0].encode())
        self.commit()

    def test_legacy_remains_approved(self):
        self.legacy()
        self.assertEqual(validate_caller(self.caller), APPROVED_REVIEWER_SHAS[0])
        validate_contract(self.contract)

    def test_migration_retains_legacy_security_suite(self):
        self.migrate()
        # Sparse proposed checkout does not materialize the shared data files.
        for name in self.shared_data:
            (self.root / name).unlink()
        self.assertEqual(validate_caller(self.caller), APPROVED_REVIEWER_SHAS[0])
        validate_contract(self.contract)

    def test_mixed_installations_are_denied(self):
        self.legacy()
        for name, data in self.shared_data.items():
            with self.subTest(name=name):
                original = self.contract.read_bytes()
                self.write(name, data)
                self.commit()
                with self.assertRaises(ValueError):
                    validate_caller(self.caller)
                if name == ".github/workflows/review-caller-contract.yaml":
                    self.contract.write_bytes(original)
                else:
                    (self.root / name).unlink()
                self.commit()

    def test_partial_and_tampered_installations_are_denied(self):
        self.migrate()
        for name, data in self.shared_data.items():
            with self.subTest(name=name):
                for changed in [None, data + b"changed\n", b"x" * (MAX_WORKFLOW_BYTES + 1)]:
                    if changed is None:
                        (self.root / name).unlink()
                    else:
                        self.write(name, changed)
                    self.commit()
                    for check, path in [(validate_caller, self.caller), (validate_contract, self.contract)]:
                        with self.assertRaises(ValueError):
                            check(path)
                    self.write(name, data)
                    self.commit()

    def test_unexpected_workflow_is_denied(self):
        self.migrate()
        self.write(".github/workflows/unapproved.yml", b"name: other\n")
        self.commit()
        with self.assertRaises(ValueError):
            validate_caller(self.caller)

    def test_symlink_and_executable_blob_are_denied(self):
        self.migrate()
        name = next(iter(self.shared_data))
        path = self.root / name
        path.unlink()
        path.symlink_to("elsewhere")
        self.commit()
        with self.assertRaises(ValueError):
            validate_caller(self.caller)
        path.unlink()
        self.write(name, self.shared_data[name])
        path.chmod(0o755)
        self.commit()
        with self.assertRaises(ValueError):
            validate_caller(self.caller)

    def test_object_read_failure_is_denied(self):
        self.migrate()
        actual = git_output
        def fail_blob(root, *arguments):
            if arguments[:2] == ("cat-file", "blob"):
                raise subprocess.CalledProcessError(1, "git cat-file")
            return actual(root, *arguments)
        with mock.patch.dict(globals(), git_output=fail_blob):
            with self.assertRaises(subprocess.CalledProcessError):
                validate_caller(self.caller)

    def test_object_corruption_is_denied(self):
        self.migrate()
        actual = git_output
        def corrupt_blob(root, *arguments):
            data = actual(root, *arguments)
            if arguments[:2] == ("cat-file", "blob"):
                return bytes([data[0] ^ 1]) + data[1:]
            return data
        with mock.patch.dict(globals(), git_output=corrupt_blob):
            with self.assertRaisesRegex(ValueError, "Git identity"):
                validate_caller(self.caller)


if __name__ == "__main__":
    unittest.main()
