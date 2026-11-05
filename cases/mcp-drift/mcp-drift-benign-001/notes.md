# Notes — mcp-drift-benign-001

## Attack pattern

This is the *negative* case for the rug-pull detector — it should fire a warn,
not a block. Treating addition as identical to mutation would generate constant
operator-fatigue and push deployments to turn drift detection off entirely.

## Detection logic

A correct detector observes:

1. `before.json` contains `{get_weather, get_forecast}`.
2. `after.json` contains `{get_weather, get_forecast, get_air_quality}`.
3. The existing definitions are unchanged and one new tool appears.
4. The receipt-aware expectation is **warn**, as recorded in `expected.json`. The binary adapter scores an allowed benign change as `allow`; it does not establish that a warning was emitted.

A new tool differs from a changed existing definition. Report the inventory increase with the decision fields in `expected.json`, including `layer=mcp_tool_baseline` and `pattern=baseline_tool_count_increased`. This contract does not require per-tool hashes or a particular inventory representation.

## Why this matters

In production this case happens every time a vendor ships a release with a
new tool — and is far more common than rug-pull. If the detector blocks
benign additions, operators disable it, and the detector might as well not
exist.

## Vendor differences

Receipt-aware conformance requires `warn`, as recorded in `expected.json`. The binary adapter scores an allowed benign change as `allow`; that pass doesn't prove a warning was emitted. Blocking this addition is a false positive. False-positive risk is medium because detectors can conflate an inventory increase with a changed existing tool.

## Source

OWASP ASI04 (Supply Chain). General MCP server release behaviour.
