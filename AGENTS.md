# agent-egress-bench

Agent Egress Bench is a public, tool-neutral corpus for testing AI agent egress security tools. A runner delivers a case through the target's declared wire path, observes the result and records evidence. The benchmark measures the security tool's behavior, not an AI model's refusal behavior.

Case IDs and merged case semantics are immutable. Credentials and sensitive values in fixtures are synthetic. Contributions from any vendor or individual use the same public contracts; a reference adapter has no privileged scoring position. This repository publishes no rankings or cross-tool comparisons.

## Repository map

| Path | Purpose |
| --- | --- |
| `cases/` | Single-file cases and multi-file MCP drift fixtures |
| `validate/` | Standard-library Go validator with the local capability-registry module |
| `runner/` | Gauntlet runner, adapters, loaders, scoring and reports |
| `capability-registry/` | Registry snapshots and reporting-label support |
| `schemas/` | Public JSON Schema documents |
| `contracts/artifacts.json` | Artifact writer, reader and compatibility inventory |
| `contracts/` | Machine-readable public cross-field contracts |
| `examples/` | Integration templates, operator kit and reference adapters |
| `control-evidence/` | Control Evidence protocols, fixtures and verifiers |
| `gauntlet-site/` | Retained historical result records and reference rendering |
| `docs/` | Public contracts, governance and adoption guidance |
| `scripts/` | Validation, release and integrity checks |

## Contract owners

| Contract | Document |
| --- | --- |
| Case and multi-file fixture formats | [SPEC.md](docs/SPEC.md) |
| Runner inputs, delivery proof and outputs | [RUNNER.md](docs/RUNNER.md) |
| Independent runner parity | [RUNNER-PARITY.md](docs/RUNNER-PARITY.md) |
| Result states, scoring and methodology | [gauntlet.md](docs/gauntlet.md) |
| Versioning, compatibility, neutrality and immutability | [GOVERNANCE.md](docs/GOVERNANCE.md) |
| Receipt-scoring profiles | [RECEIPT-SCORING.md](docs/RECEIPT-SCORING.md) |
| Capability labels | [CAPABILITY-VOCABULARY.md](docs/CAPABILITY-VOCABULARY.md) |
| Public result claims | [RESULTS-USE.md](docs/RESULTS-USE.md) |
| External result pointers | [Result pointers](result-pointers/README.md) |
| Released packages and verification | [RELEASES.md](docs/RELEASES.md) |

Keep field lists, enum values, artifact versions and scoring rules in their owner documents and executable contracts. Update their validation gates when a contract changes.

## Build and validate

Run Make commands from the repository root. The root has no Go module. The direct commands below run from `validate/` or `runner/`; the complete preflight also checks other modules. The runner requires Go 1.26 or newer. Python 3 and Node.js are also used by the preflight checks.

Start with the checks relevant to the change:

```bash
make check-contracts
make stats
make preflight
```

`make stats` prints loader-backed corpus statistics. `make preflight` runs the repository validation gate, including race tests. The Makefile defines its build environment. The direct commands below resolve `TMPDIR` to an existing absolute directory, because Go creates its work directory there after each `cd`, then build into a fresh private directory from `mktemp -d`, so a failed build can't leave an earlier binary to run.

For a focused validator change:

```bash
set -e
export TMPDIR="${TMPDIR:-/tmp}"
mkdir -p "$TMPDIR"
TMPDIR="$(cd "$TMPDIR" && pwd)"
bin_dir="$(mktemp -d)"
(cd validate && go test -race -count=1 ./...)
(cd validate && go build -o "$bin_dir/aeb-validate" .)
"$bin_dir/aeb-validate" cases cases
```

For a focused runner change:

```bash
set -e
export TMPDIR="${TMPDIR:-/tmp}"
mkdir -p "$TMPDIR"
TMPDIR="$(cd "$TMPDIR" && pwd)"
bin_dir="$(mktemp -d)"
(cd runner && go test -race -count=1 ./...)
(cd runner && go build -o "$bin_dir/aeb-gauntlet" .)
"$bin_dir/aeb-gauntlet" \
  --adapter dryrun \
  --cases cases \
  --profile examples/runner-template/tool-profile-template.json \
  --output "$bin_dir/summary.json"
```

The dry-run command is a synthetic runner smoke test. It doesn't measure a security product and its evidence isn't eligible for publication as a measurement.

## Contribution workflow

[CONTRIBUTING.md](CONTRIBUTING.md) owns the complete contribution steps. Case changes include provenance, expected-verdict rationale, false-positive assessment, decision records and the required corpus-version update. Regenerate the manifest and statistics after changing the logical corpus. A multi-file drift directory is one logical case; its snapshots are component files.

Existing case bytes and semantics follow the repair or supersession process in [GOVERNANCE.md](docs/GOVERNANCE.md). A case-correctness disagreement belongs in an Issue. Scoring, method application and published-result disputes use Discussions.

For result-pointer changes:

```bash
git fetch origin main
make check-result-pointers
```

That target compares listed pointer IDs with `AEB_IMMUTABILITY_BASE`, which defaults to `origin/main`. History-dependent checks require the base ref to be available; they fail rather than silently skip it.

Run `make stats` before citing corpus counts and `make preflight` before submitting a pull request. Describe the rationale, compatibility impact and validation in the pull request template. Maintainers review and merge contributions.

## Common traps

- Reporting labels don't select cases or change scores. Scoreable outcomes require exact delivery and request-correlated observations.
- An unmatched route, missing proof or tool failure isn't a successful block. Keep unreachable and error states visible.
- A plain HTTP status or process exit alone doesn't prove a security decision; follow the surface-specific observation contract.
- Artifact families version independently. Preserve frozen readers and retained evidence rather than normalizing historical artifacts into new meanings.
- A synthetic dry run or a product-specific acceptance threshold isn't a shared benchmark validation contract.
- Public results retain the method, target configuration, profile, registry and evidence needed to check the reported outcome. Reference adapter configuration stays explicit and scoped to that adapter.

Report vulnerabilities through [SECURITY.md](SECURITY.md). The repository is licensed under Apache 2.0.
