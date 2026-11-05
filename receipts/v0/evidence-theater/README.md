# Evidence Theater Kill Suite (v0)

A vendor-neutral corpus of **agent-control evidence packets that look valid and
sound strong but overclaim** — each paired with the exact appraisal a correct
verifier must emit to downgrade it. Where `receipts/v0/conformance/` tests that a
verifier accepts good evidence and rejects forged evidence, this suite tests a
harder property: that a verifier refuses to call an assertion "proven" beyond what
the evidence *mechanically* supports, and names the over-read out loud.

The premise is simple and uncomfortable: a valid signature, a valid workload
identity, a hash-chain link, a witnessed checkpoint — each proves something
narrow, and each is routinely read as proving something much broader. "Signed by
the mediator" is read as "every action was mediated." "Has a verified workload
identity" is read as "its network egress cannot bypass the mediator." Those reads
are wrong, and a credible verifier says so. This corpus is the set of packets that
tempt the wrong read, plus the appraisal that resists it.

## Fixture provenance

Some retained fixtures use the `pipelock_shaped` metadata label to identify a product-shaped example. That label is fixture metadata; it gives the product no benchmark status. Every fixture is judged by the same declared claims and expected appraisal, regardless of its source.

## What each fixture is

Every fixture is an assurance **envelope** (`*.aarp.json`), optionally with an
X.509-SVID workload-identity sidecar (`*.svid.json`), plus:

- `*.expect.json` — metadata, the verdict (`appraise`), the attack class, and the
  overclaim annotations a correct verifier must satisfy:
  - `overclaim_narrative` — the broad property a naive relying party might read in.
  - `must_not_verify` — claims that MUST be absent from the verifier's
    `verified_claims` (the over-broad reads the evidence does not support).
  - `expected_overclaim_risks` — risk codes the verifier MUST raise.
  - `expected_does_not_assert` — negatives the verifier MUST list.
  - `pipelock_shaped` — true when genuine, validly-signed reference-tool evidence
    is still downgraded.
- `*.appraisal.json` — the exact comparable appraisal bytes any conformant
  verifier MUST emit (the cross-language equality surface).

`trust.json` and `test-keys.json` pin the deterministic test keys so any verifier
can reproduce the appraisals. **Test material only — never production keys.**

## Attack classes

The suite covers, among others: a valid signature over an omitted/partial action;
a valid SVID that proves identity but not network non-bypass; a hash-chain link
with no proven session start; a wrong-purpose / wrong-role signing key; a missing
policy hash on a default-allow; a deployment claim with no attestor; a modify
receipt with no semantic-equivalence proof; self-attested complete mediation; a
substituted (untrusted) signer; identity-as-deployment axis laundering; parallel-
signature confusion; a critical-extension downgrade; claim-alias sprawl; scope
smuggling; bundling a valid assertion with unverifiable receipts; and cross-
language confusable drift. At least five fixtures downgrade reference-tool-shaped
evidence.

## Running a verifier against it

Point any conformant agent-assurance verifier at each `*.aarp.json` (with its
`*.svid.json` sidecar when present) and `trust.json`, and compare its comparable
output to the committed `*.appraisal.json`. A verifier that emits a `verified`
claim listed in a fixture's `must_not_verify`, or omits an `expected_overclaim_risks`
entry, is overclaiming.

## Provenance

This directory retains fixture inputs and expected appraisals. Run `receipts/v0/evidence-theater/validate.sh` from the repository root to check the mirror's structural integrity. That command doesn't regenerate the reference appraisals or establish byte equality with an upstream generator. The repository doesn't provide a pinned generator checkout and reproduction command for these artifacts.
