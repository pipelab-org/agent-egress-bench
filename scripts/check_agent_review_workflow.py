"""Validate proposed caller policy using the trusted default-branch definition."""

import argparse
import os
import pathlib
import re
import stat

# Existing caller-policy contract: approve a source/shape on main, migrate,
# then remove the predecessor approval. Never execute proposed target code.
MAX_WORKFLOW_BYTES = 65536
APPROVED_REVIEWER_SHAS = ("856e474c1697f3897ccaa156f083e0b9504196e0",)
EXPECTED_CONTRACTS = ('name: Review caller contract\n\non:\n  pull_request:\n    types: [opened, synchronize, reopened]\n    paths:\n      - \'.github/workflows/agent-review.yaml\'\n      - \'.github/agent-review.toml\'\n      - \'.github/workflows/review-caller-contract.yaml\'\n      - \'scripts/check_agent_review_workflow.py\'\n  pull_request_target:\n    types: [opened, synchronize, reopened]\n    paths:\n      - \'.github/workflows/agent-review.yaml\'\n      - \'.github/agent-review.toml\'\n      - \'.github/workflows/review-caller-contract.yaml\'\n      - \'scripts/check_agent_review_workflow.py\'\n  push:\n    branches: [main]\n    paths:\n      - \'.github/workflows/agent-review.yaml\'\n      - \'.github/agent-review.toml\'\n      - \'.github/workflows/review-caller-contract.yaml\'\n      - \'scripts/check_agent_review_workflow.py\'\n\npermissions:\n  contents: read\n\njobs:\n  contract:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - name: Check out the caller validator\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n        with:\n          # Bootstrap tests run proposed code without secrets. Target validation\n          # always runs the default-branch copy, independently of proposed code.\n          repository: ${{ github.event_name == \'pull_request\' && github.event.pull_request.head.repo.full_name || github.repository }}\n          ref: ${{ github.event_name == \'pull_request\' && github.event.pull_request.head.sha || github.sha }}\n          allow-unsafe-pr-checkout: true\n          path: trusted-validator\n          persist-credentials: false\n          sparse-checkout: scripts/check_agent_review_workflow.py\n          sparse-checkout-cone-mode: false\n      - name: Check out proposed policy as data\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name || github.repository }}\n          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n          allow-unsafe-pr-checkout: true\n          path: proposed\n          persist-credentials: false\n          sparse-checkout: |\n            .github/workflows/agent-review.yaml\n            .github/agent-review.toml\n            .github/workflows/review-caller-contract.yaml\n          sparse-checkout-cone-mode: false\n      - name: Check approved source and checking workflow before loading shared code\n        id: policy\n        run: python3 -I trusted-validator/scripts/check_agent_review_workflow.py --root proposed --output "$GITHUB_OUTPUT"\n      - name: Check out the approved immutable shared validator\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n        with:\n          repository: pipelab-org/agent-review\n          ref: ${{ steps.policy.outputs.reviewer_sha }}\n          path: trusted-reviewer\n          persist-credentials: false\n          sparse-checkout: scripts/agent_review_contract.py\n          sparse-checkout-cone-mode: false\n      - name: Validate caller and profile with approved shared code\n        env:\n          REVIEW_SOURCE_SHA: ${{ steps.policy.outputs.reviewer_sha }}\n        run: |\n          python3 -I - <<\'PYCODE\'\n          import os\n          import pathlib\n          import runpy\n\n          contract = runpy.run_path("trusted-reviewer/scripts/agent_review_contract.py")\n          root = pathlib.Path("proposed")\n          contract["validate_caller"](\n              root / ".github/workflows/agent-review.yaml", os.environ["REVIEW_SOURCE_SHA"],\n          )\n          contract["load_profile"](root / ".github/agent-review.toml")\n          print("Review caller and profile contract passed")\n          PYCODE\n',)


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



def validate_policy(root):
    root = pathlib.Path(root)
    caller = read_workflow(root / ".github/workflows/agent-review.yaml")
    pins = re.findall(
        r"^    uses: pipelab-org/agent-review/\.github/workflows/agent-review-reusable\.yaml@([0-9a-f]{40}) # main$",
        caller, re.MULTILINE,
    )
    if len(pins) != 1 or pins[0] not in APPROVED_REVIEWER_SHAS:
        raise ValueError("approve the immutable reviewer source on main before migrating")
    contract = read_workflow(root / ".github/workflows/review-caller-contract.yaml")
    if contract not in EXPECTED_CONTRACTS:
        raise ValueError("proposed checking workflow differs from its trusted definition")
    return pins[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        reviewer_sha = validate_policy(args.root)
    except (OSError, ValueError):
        parser.exit(1, "Invalid proposed reviewer source or checking workflow\n")
    with args.output.open("a", encoding="utf-8") as output:
        output.write(f"reviewer_sha={reviewer_sha}\n")
    print("Trusted reviewer-source and checking-workflow contract passed")


if __name__ == "__main__":
    main()
