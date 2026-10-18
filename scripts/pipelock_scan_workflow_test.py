#!/usr/bin/env python3
"""Structural tests for the Pipelock secret-scan workflow.

Each assertion corresponds to a defect caught by a human reviewer rather than by
any check, which is why they are tests and not comments.

The scan workflow was rewritten on 2026-08-10 because the published Pipelock
action installs the latest RELEASE, and a scanner fix on Pipelock's default
branch does not reach a release for weeks. Whole-file-deletion hunk parsing was
fixed in pipelock#1145, which was absent from v3.3.0, so every pull request that
deleted a file failed with "unverifiable input: content outside unified diff
hunks" and the action surfaced that as "Secrets detected in PR diff" with no
secret present. That blocked #157 for a day.

These assertions target the EXECUTABLE path, never workflow prose. An earlier
version of this file searched the raw workflow text, which meant a file with two
no-op steps and the pinned revision sitting inside a COMMENT would have passed
every check while invoking no scanner at all. Review caught that. Matching on
step display names or on any occurrence of a command in the file is decoration:
the contract is the command that actually runs, reached through the parsed
event condition.
"""

import re
import shlex
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "pipelock.yaml"

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SCAN_COMMAND = "pipelock git scan-diff"

# The two events that must each reach a scan, keyed by the condition the step
# is actually gated on rather than by its display name.
REQUIRED_EVENTS = {
    "pull_request": "github.event_name == 'pull_request'",
    "workflow_dispatch": "github.event_name == 'workflow_dispatch'",
}


def load_workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def scan_job(workflow):
    jobs = workflow.get("jobs") or {}
    job = jobs.get("security-scan")
    if job is None:
        raise AssertionError(
            "no security-scan job; if the job was renamed, update this test rather than deleting it"
        )
    return job


def steps_running(job, needle):
    """Steps whose executed shell actually contains needle."""
    return [s for s in (job.get("steps") or []) if needle in (s.get("run") or "")]


# Verified tag commits: each row is what `git ls-remote
# https://github.com/luckyPipewrench/pipelock refs/tags/vX.Y.Z^{}` peels to.
# A row records a fact about the tag, not approval to deploy it here; that
# approval is the reviewed change that moves all three producer pins together.
# Never derive a row from the workflow.
RELEASE_COMMITS = {
    "3.6.0": "3e868ac5d5b62d3a2790958542171143af8a0e38",
    "3.7.0": "47c14c59b14f835f53971d22941b556f44f2baa0",
}
# The repository moved from luckyPipewrench to pipelab-org. GitHub owner and
# repository names are case-insensitive, so either owner in any case names the
# same repository action. jobs.<job_id>.steps[*].uses also selects
# owner/repo/path@ref, which is a different action in that repository. A path
# still has to count, or a second step hides beside the pinned root action.
# It cannot satisfy the one repository-root producer. The ref is compared
# case-sensitively in _same_commit.
ACTION_OWNERS = ("luckyPipewrench", "pipelab-org")
ACTION_USES = re.compile(
    r"^(?P<owner>[^/@]+)/pipelock(?P<path>/[^@]+)?@(?P<ref>.*)$",
    re.IGNORECASE,
)
INSTALL_REF = re.compile(r"cmd/pipelock@(\S+)")


def _action_steps(job):
    """All Pipelock action steps, including unrecognized owners."""
    found = []
    for step in job.get("steps") or []:
        match = ACTION_USES.match(str(step.get("uses") or ""))
        if match:
            found.append((step, match.group("ref")))
    return found


def _install_refs(job):
    """The revision each `go install ...cmd/pipelock@REF` really consumes.

    Resolved through the installing step's own env, so an unused variable
    elsewhere cannot stand in for the revision the build uses.
    """
    refs = []
    for step in job.get("steps") or []:
        run = step.get("run") or ""
        if "go install" not in run:
            continue
        env = step.get("env") or {}
        for match in INSTALL_REF.finditer(run):
            ref = match.group(1)
            # This workflow uses one direct install after `set -euo pipefail`.
            # Reject other shell prefixes instead of interpreting arbitrary
            # shell that could replace the step's pinned environment value.
            start = run.rfind("\n", 0, match.start()) + 1
            end = run.find("\n", match.end())
            line = run[start:] if end == -1 else run[start:end]
            # $(...) and backticks are command substitutions (POSIX). They run
            # even inside the one GOBIN assignment this workflow uses.
            # ${NAME} is the parameter expansion that workflow actually has.
            if "$(" in line or "`" in line:
                refs.append("<unverifiable shell install>")
                continue
            preceding = [s.strip() for s in run[:start].splitlines()]
            safe_prefix = all(not s or s.startswith("#") or s == "set -euo pipefail" for s in preceding)
            # shlex.split keeps runs of ;|&<>() inside a word, so a GOBIN
            # assignment can hide another assignment. punctuation_chars=True
            # separates that published set. split() has no such argument;
            # whitespace_split and empty commenters are what split() uses.
            try:
                lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
                lexer.whitespace_split = True
                lexer.commenters = ""
                words = list(lexer)
            except ValueError:
                words = []
            if words and words[0].startswith("GOBIN="):
                words = words[1:]
            if not safe_prefix or len(words) != 3 or words[:2] != ["go", "install"]:
                refs.append("<unverifiable shell install>")
                continue
            ref = ref.strip('"').strip("'")
            expansion = re.fullmatch(r"\$\{?(\w+)\}?", ref)
            if expansion:
                if "'" in line:
                    refs.append("<quoted literal variable>")
                    continue
                key = expansion.group(1)
                ref = str(env[key]).strip() if key in env else f"<unset ${key}>"
            refs.append(ref)
    return refs


def _same_commit(value, commit):
    """Exact, full-length, case-sensitive comparison; no prefixes."""
    return value == commit


def producer_pin_problems(job):
    """Disagreements between the action ref, its version input and the built scanner."""
    actions = _action_steps(job)
    owners = " or ".join(f"{o}/pipelock@<commit>" for o in ACTION_OWNERS)
    if not actions:
        return [f"no Pipelock action step found; expected exactly one step using {owners}"]
    if len(actions) > 1:
        names = ", ".join(str(step.get("uses")) for step, _ in actions)
        return [f"found {len(actions)} Pipelock action steps ({names}); expected exactly one using {owners}"]
    installs = _install_refs(job)
    if len(installs) != 1:
        return [f"expected exactly one `go install ...cmd/pipelock@<commit>`, found {len(installs)}: {installs!r}"]
    step, action_ref = actions[0]
    parsed = ACTION_USES.fullmatch(str(step["uses"]))
    owner = parsed.group("owner")
    if owner.lower() not in {o.lower() for o in ACTION_OWNERS}:
        return [f"unrecognized Pipelock action owner {owner!r}; expected {owners}"]
    if parsed.group("path"):
        shown = str(step.get("uses"))
        return [
            f"Pipelock action {shown!r} selects a subdirectory action; "
            f"expected exactly one repository-root step using {owners}"
        ]
    version = str((step.get("with") or {}).get("version") or "")
    commit = RELEASE_COMMITS.get(version)
    if commit is None:
        return [f"action version {version!r} is not a verified release in RELEASE_COMMITS"]
    pins = (("action ref", action_ref), ("installed scanner revision", installs[0]))
    return [
        f"{label} {value!r} is not the release commit {commit} for version {version}; "
        "advance the audit config producer and source-pinned scanner together after proving compatibility"
        for label, value in pins
        if not _same_commit(value, commit)
    ]


def drift_job(version="3.6.0", action=None, owner="luckyPipewrench", install="env",
              rev=None, decoy=None, extra_actions=(), with_install=True,
              repository="pipelock"):
    """A minimal security-scan job for the drift table.

    install="env" builds from ${PIPELOCK_REV}; "other" builds from
    ${SCANNER_REV}; "unset" reads ${SCANNER_REV} without defining it;
    "literal" names the commit in the command itself.
    decoy sets an unused PIPELOCK_REV beside a non-"env" install.
    """
    base = RELEASE_COMMITS["3.6.0"]
    action = base if action is None else action
    rev = base if rev is None else rev
    with_block = {} if version is None else {"version": version}
    steps = [{"uses": f"{owner}/{repository}@{action}", "with": with_block}]
    steps += [{"uses": uses, "with": {"version": v}} for uses, v in extra_actions]
    if with_install:
        if install == "env":
            env, ref = {"PIPELOCK_REV": rev}, "${PIPELOCK_REV}"
        elif install == "other":
            env, ref = {"SCANNER_REV": rev}, "${SCANNER_REV}"
        elif install == "unset":
            env, ref = {}, "${SCANNER_REV}"
        else:
            env, ref = {}, rev
        if decoy is not None:
            env["PIPELOCK_REV"] = decoy
        steps.append({
            "env": env,
            "run": f'go install "github.com/luckyPipewrench/pipelock/cmd/pipelock@{ref}"',
        })
    return {"steps": steps}


class PipelockScanWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = load_workflow()
        self.job = scan_job(self.workflow)

    def test_both_events_reach_a_real_scan(self):
        """Each trigger must reach a step that actually runs the scanner.

        Promotion pull requests are created with GITHUB_TOKEN and do not emit a
        pull_request run, so the promotion workflow dispatches this one against
        the generated branch instead. Losing either path leaves a class of
        change entering main unscanned, and the loss is invisible because the
        surviving path still reports success.
        """
        triggers = self.workflow.get(True) or self.workflow.get("on") or {}
        for event in REQUIRED_EVENTS:
            self.assertIn(
                event,
                triggers,
                f"{event} trigger removed; that class of change would go unscanned",
            )

        scanning = steps_running(self.job, SCAN_COMMAND)
        self.assertTrue(
            scanning,
            f"no step actually runs {SCAN_COMMAND!r}; the job may look intact while scanning nothing",
        )

        conditions = [str(s.get("if") or "") for s in scanning]
        for event, condition in REQUIRED_EVENTS.items():
            self.assertTrue(
                any(condition in c for c in conditions),
                f"no scanning step is gated on {condition!r}; {event} would run the job without scanning",
            )

    def test_scanner_is_built_from_an_immutable_pinned_revision(self):
        """The executed install command must consume a pinned commit.

        Asserting that a 40-character SHA appears somewhere in the file is not
        enough: the real install could use a moving ref while an unrelated or
        commented value satisfies the pattern. The pin only counts if the
        command that installs the scanner consumes it.
        """
        installing = steps_running(self.job, "go install")
        self.assertTrue(installing, "no step installs the scanner")

        for step in installing:
            run = step["run"]
            env = step.get("env") or {}

            module_refs = re.findall(r"cmd/pipelock@(\S+)", run)
            self.assertTrue(
                module_refs,
                f"install command does not name a pipelock revision:\n  {run.strip()}",
            )

            for ref in module_refs:
                ref = ref.strip('"').strip("'")
                # The ref is normally an env expansion; resolve it before judging.
                expansion = re.fullmatch(r"\$\{?(\w+)\}?", ref)
                if expansion:
                    key = expansion.group(1)
                    self.assertIn(
                        key,
                        env,
                        f"install consumes ${key} but the step does not define it, so the pinned "
                        "revision cannot be verified here",
                    )
                    resolved = str(env[key]).strip()
                else:
                    resolved = ref

                self.assertRegex(
                    resolved,
                    FULL_SHA,
                    f"scanner installed from {resolved!r}; pin a full 40-character commit so a later "
                    "upstream commit cannot silently change or disable this gate",
                )

    def test_audit_config_producer_is_version_pinned(self):
        """The audit config must not drift ahead of the pinned scanner.

        The action (with its ``version`` input) produces the config and the
        scanner built by ``go install`` parses it. The action ref, the version
        and the revision the install command actually consumes must all name
        the same verified release.
        """
        self.assertEqual([], producer_pin_problems(self.job))

    def test_producer_pin_check_rejects_each_drift(self):
        """Every drift is reported and every coordinated move is accepted.

        Runs on synthetic jobs so the table does not depend on the release the
        workflow currently uses. Each "rejects" row pins one property of the
        checker: exact length, exact case, one action step, a present install,
        exactly one install (counted across steps and within one run),
        an un-normalised version, the consumed revision, and both owners.
        """
        new = RELEASE_COMMITS["3.7.0"]
        old = RELEASE_COMMITS["3.6.0"]
        MODULE = "github.com/luckyPipewrench/pipelock/cmd/pipelock"
        cases = (
            # (name, job, expected substring or None for no problems)
            ("positive control: unchanged", drift_job(), None),
            ("positive control: all three advanced together",
             drift_job(version="3.7.0", action=new, rev=new), None),
            ("positive control: action under pipelab-org", drift_job(owner="pipelab-org"), None),
            ("positive control: owner in another case", drift_job(owner="LUCKYPIPEWRENCH"), None),
            ("positive control: repository name in another case",
             drift_job(repository="Pipelock"), None),
            ("version advanced alone", drift_job(version="3.7.0"), "not the release"),
            ("version not a verified release", drift_job(version="9.9.9"), "not a verified release"),
            ("version left floating", drift_job(version="latest"), "not a verified release"),
            ("version removed", drift_job(version=None), "not a verified release"),
            ("version with a leading v", drift_job(version="v3.6.0"), "not a verified release"),
            ("action advanced alone", drift_job(action=new), "action ref"),
            ("action on a moving ref", drift_job(action="main"), "action ref"),
            ("action ref is a short prefix", drift_job(action=old[:8]), "action ref"),
            ("action ref in upper case", drift_job(action=old.upper()), "action ref"),
            ("scanner advanced alone", drift_job(rev=new), "installed scanner revision"),
            ("scanner revision is a short prefix", drift_job(rev=old[:8]), "installed scanner revision"),
            ("install reads another variable, PIPELOCK_REV left as decoy",
             drift_job(install="other", rev=new, decoy=old), "installed scanner revision"),
            ("literal ref in install, PIPELOCK_REV left as decoy",
             drift_job(install="literal", rev=new, decoy=old), "installed scanner revision"),
            ("install variable unset, PIPELOCK_REV left as decoy",
             drift_job(install="unset", decoy=old), "installed scanner revision"),
            ("install step removed", drift_job(with_install=False), "expected exactly one `go install"),
            ("second install, advanced",
             {"steps": drift_job()["steps"] + [{"run": f'go install "{MODULE}@{new}"'}]},
             "expected exactly one `go install"),
            ("one run installs twice",
             {"steps": drift_job(with_install=False)["steps"] + [
                 {"env": {}, "run": f'go install "{MODULE}@{old}" && go install "{MODULE}@{new}"'}]},
             "expected exactly one `go install"),
            ("second action step, same owner",
             drift_job(extra_actions=(("luckyPipewrench/pipelock@" + new, "3.7.0"),)), "found 2 Pipelock action steps"),
            ("second action step, other owner",
             drift_job(extra_actions=(("pipelab-org/pipelock@" + new, "3.7.0"),)), "found 2 Pipelock action steps"),
            ("second action step, repository name in another case",
             drift_job(extra_actions=(("luckyPipewrench/Pipelock@main", "3.7.0"),)), "found 2 Pipelock action steps"),
            ("second action step, subpath action",
             drift_job(extra_actions=(("luckyPipewrench/pipelock/sub@main", "3.7.0"),)), "found 2 Pipelock action steps"),
            ("subdirectory action replaces the repository action",
             drift_job(repository="pipelock/sub"), "selects a subdirectory action"),
            ("nested action path replaces the repository action",
             drift_job(repository="pipelock/.github/workflows/other.yml"), "selects a subdirectory action"),
            ("action owner unknown", drift_job(owner="someone-else"), "unrecognized Pipelock action owner"),
            ("second action step, unknown owner",
             drift_job(extra_actions=(("someone-else/pipelock@main", "3.7.0"),)), "found 2 Pipelock action steps"),
        )
        for prefix in (f"export PIPELOCK_REV={new}\n", f"PIPELOCK_REV={new}\n",
                       f"PIPELOCK_REV={new} ", f"read PIPELOCK_REV\n"):
            job = drift_job()
            job["steps"][-1]["run"] = prefix + job["steps"][-1]["run"]
            cases += ((f"shell changes the revision: {prefix!r}", job, "installed scanner revision"),)
        job = drift_job()
        job["steps"][-1]["run"] = f"go install '{MODULE}@${{PIPELOCK_REV}}'"
        cases += (("single-quoted variable is literal", job, "installed scanner revision"),)
        for gobin in (
            'GOBIN="$(echo /tmp)" ',
            'GOBIN="`echo /tmp`" ',
            'GOBIN="${RUNNER_TEMP:-$(echo /tmp)}/bin" ',
        ):
            job = drift_job()
            job["steps"][-1]["run"] = "set -euo pipefail\n" + gobin + job["steps"][-1]["run"]
            cases += ((f"command substitution in GOBIN: {gobin!r}", job, "installed scanner revision"),)
        # No space around the operator: shlex.split used to swallow it into
        # the one allowed GOBIN word and then trust the step environment.
        for operator in (";", "&&", "|", "||", "&", ">", "<", "(", ")"):
            prefix = f"GOBIN=/x{operator}PIPELOCK_REV={new}{operator} "
            job = drift_job()
            job["steps"][-1]["run"] = "set -euo pipefail\n" + prefix + job["steps"][-1]["run"]
            cases += ((f"shell operator inside GOBIN: {prefix!r}", job, "installed scanner revision"),)
        for gobin in (
            'GOBIN="${RUNNER_TEMP}/bin" ',
            "GOBIN=/tmp ",
            'GOBIN="/x;PIPELOCK_REV=ignored" ',
        ):
            job = drift_job()
            job["steps"][-1]["run"] = "set -euo pipefail\n" + gobin + job["steps"][-1]["run"]
            cases += ((f"ordinary GOBIN assignment: {gobin!r}", job, None),)
        for name, job, expected in cases:
            with self.subTest(name):
                problems = producer_pin_problems(job)
                if expected is None:
                    self.assertEqual([], problems)
                else:
                    self.assertTrue(
                        any(expected in p for p in problems),
                        f"{name}: drift not reported, got {problems!r}",
                    )

    def test_scanned_diff_is_generated_with_text(self):
        """The diff feeding the scanner must be generated with --text.

        Without it a path marked binary by an in-repo .gitattributes reduces to
        a "Binary files differ" marker and its content is never scanned, so a
        credential can be added behind a one-line attributes rule.

        Only the diff that actually feeds the scanner is checked. Requiring
        every git diff in the file to carry --text would reject legitimate
        non-scanning uses such as `git diff --quiet`.
        """
        scanning = steps_running(self.job, SCAN_COMMAND)
        self.assertTrue(scanning, "no scanning step to check")

        for step in scanning:
            # Join continuations so a multi-line command is judged whole.
            run = re.sub(r"\\\s*\n\s*", " ", step["run"])
            diff_commands = [
                line.strip()
                for line in run.splitlines()
                if "git diff" in line and ">" in line
            ]
            self.assertTrue(
                diff_commands,
                f"scanning step {step.get('name')!r} does not generate a diff file it then scans",
            )
            for command in diff_commands:
                self.assertIn(
                    "--text",
                    command,
                    f"diff feeding the scanner is generated without --text:\n  {command}\n"
                    "an in-repo .gitattributes rule could hide added content from the scanner",
                )


if __name__ == "__main__":
    unittest.main()
