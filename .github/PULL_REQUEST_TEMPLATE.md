## What and why

What does this PR add or change, and why is it needed?

## Case rationale and provenance

For case changes: where the pattern comes from (a citation, or how you constructed it), why the expected verdict is right, and the false-positive risk. Name related benign controls, or say why none apply.

## Compatibility

Does this change existing case bytes, artifact contracts, the corpus version, scoring or downstream readers? Explain any version change or supersession, or say why none is needed.

## Validation

List the commands you ran and what they reported, and any check you couldn't run.

## Checklist

- [ ] Followed the applicable procedure in CONTRIBUTING.md
- [ ] `make preflight` passes
- [ ] All secrets and sensitive values are obviously fake
- [ ] Single-file case IDs match filenames; multi-file case IDs match directory names
- [ ] New cases include `description`, `why_expected`, `false_positive_risk` and `source`
- [ ] Single-file benign cases have `"safe_example": true`
