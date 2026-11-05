# Contributing

Contributions welcome: new test cases, runners for your security tool, documentation, and spec improvements.

## Adding a case

1. Pick the right category directory under `cases/` (see [docs/SPEC.md](docs/SPEC.md) for the full list)
2. Follow the naming, field, and payload rules in [docs/SPEC.md](docs/SPEC.md)
3. Check immutability, provenance, and synthetic-fixture requirements in [docs/GOVERNANCE.md](docs/GOVERNANCE.md)
4. Validate the new files with `make validate-cases`.
5. Generate the decision records for the new cases and review the diff:

   ```bash
   PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate_case_governance_records.py
   ```

   `make check-case-governance` requires one record per logical case. See [Per-case governance decision records](docs/GOVERNANCE.md#per-case-governance-decision-records).
6. Regenerate the case manifest and review the change:

   ```bash
   make cases-manifest
   ```

7. Give the changed corpus a new version. Adding, removing or re-expecting a scored case needs a new label in `cases/CORPUS_VERSION` and `runner/summary.go`, a new active-set artifact under `corpora/active-sets/v1/` bound to the regenerated manifest, and a new final entry in `ci/corpus-versions.json` with its case count and digests. The same applies to editing a file that a case selects, such as the `notes.md` a multi-file case declares. Never edit existing ledger entries or artifacts. [Corpus version identity](docs/GOVERNANCE.md#corpus-version-identity) owns the rules.
8. Regenerate the statistics, review the generated changes, then run the full gate:

   ```bash
   make stats-update
   make preflight
   ```

### Existing cases are immutable

Follow the immutability and supersession process in [docs/GOVERNANCE.md](docs/GOVERNANCE.md). If you disagree with an expected verdict, open an issue before changing corpus content.

### Fake secrets, and getting your push blocked

Cases carry intentionally fake credentials, so GitHub Push Protection will reject a push that looks like a real leak. It flags shapes such as `AKIA`, `ghp_`, `xoxb-`, and `sk-live_`.

- Use obviously synthetic values. The AWS documentation example key is written here as `"AKIA" + "IOSFODNN7EXAMPLE"` because this file is scanned too, and writing that key whole would fail the repository's own secret scan.
- Split a value at the pattern boundary when a push or a scan blocks it, exactly as the line above does.
- `SG.FAKE_TEST_KEY` works for SendGrid-shaped tokens.
- Never commit a real secret, including an expired one.

A blocked push means the scanner matched a shape, not that you leaked anything. Reshape the fixture rather than bypassing the check.

## Adding a runner

Start from the [runner template](examples/runner-template/) and follow [docs/ADOPTION.md](docs/ADOPTION.md). [docs/RUNNER.md](docs/RUNNER.md) owns the profile and output contracts.

## Validation

`make validate-cases` checks case structure. Before submitting any change, run `make preflight`; CI runs the same gate on every pull request, along with CodeQL security analysis and dependency review. A pull request that changes only workflow files runs `make test-workflows` instead of the full gate.

## Governance

This repo is maintained by the Pipelock author. Contributions from any vendor or individual are welcome. This repo does not produce rankings or cross-tool comparisons. Each publisher hosts its own evidence; a mechanically admitted pointer may be listed under `result-pointers/`. Listing is not approval.

Full governance policy: [docs/GOVERNANCE.md](docs/GOVERNANCE.md). Vendor adoption guide: [docs/ADOPTION.md](docs/ADOPTION.md).
