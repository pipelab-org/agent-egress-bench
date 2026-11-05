# Runner Template

A practical guide for building a runner that connects your security tool to the agent-egress-bench corpus. This is the "how to do it" guide. For the formal contract (required fields, scoring rules), see [docs/RUNNER.md](../../docs/RUNNER.md).

## What you need

- Your tool's binary or running service
- `jq` (for JSON processing)
- The `cases/` directory from this repo
- A `tool-profile.json` declaring your tool's capabilities
- `bash` (the skeleton is a bash script, but you can write your runner in any language)
- Python 3, used by the skeleton to read the artifact contract

## Can my tool be integrated?

Use this check before writing code:

| Tool shape | Current status | What to do |
|------------|----------------|------------|
| Forward proxy with a fetch endpoint such as `/fetch?url=...` | Yes | Prove your runner can call that endpoint with the case method/body/headers and observe block signals |
| CONNECT-capable forward proxy | Yes | Prove your runner can send requests through it as an HTTPS forward proxy |
| Reverse proxy or API gateway with `listen` and `upstream` routing | Not today | Write a custom runner or leave the unmatched transports unsupported |
| In-process SDK or library | Not today | Wrap it in a runner-owned service or leave the unmatched transports unsupported |
| MCP gateway | Narrow Streamable HTTP support | Use `--adapter mcp-gateway` and a plugin. See [GATEWAY-ADAPTER.md](../../docs/GATEWAY-ADAPTER.md) for supported case shapes and limitations. |

A result is scoreable only when its adapter proves delivery of the exact wire
input and observes a verdict. Claims are registry-backed reporting labels. They
don't select cases or change a score, denominator, sufficiency decision, or
publication decision. No exact route is `unreachable`, not N/A, and makes `measurement_status` incomplete.

## Step 1: Create your tool profile

Run the copy commands from `examples/runner-template/`. Create a runner directory, copy `tool-profile-template.json` into it and fill it in.

```bash
mkdir -p ../your-tool
cp tool-profile-template.json ../your-tool/tool-profile.json
```

Edit the file. Here is what each field means:

### Top-level fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | integer | Always `4` for active scoring |
| `tool` | string | Your tool's name (lowercase, no spaces) |
| `tool_version` | string | The version you are testing against |
| `runner_version` | string | Version of your runner script (use `v1` to start) |

### `claims` array

Reporting labels for what your tool detects. They do not control selection.
Pick them from the exact capability-registry snapshot named below:

| Claim | What it means |
|-------|---------------|
| `url_dlp` | Detect secrets in URLs (query strings, paths) |
| `request_body_dlp` | Detect secrets in POST/PUT bodies |
| `header_dlp` | Detect secrets in HTTP headers |
| `response_injection` | Detect prompt injection in fetched content |
| `mcp_input_scan` | Detect secrets/injection in MCP tool arguments |
| `mcp_session_binding` | Bind MCP state to the intended session |
| `mcp_tool_result_dlp_scanning` | Detect credential material in MCP tool results |
| `mcp_tool_poison` | Detect poisoned MCP tool descriptions |
| `mcp_chain` | Detect multi-step exfiltration sequences |
| `ssrf` | Detect SSRF attempts (private IPs, metadata endpoints) |
| `domain_blocklist` | Block known-bad domains |
| `entropy` | Detect high-entropy strings (potential encoded secrets) |
| `encoding_evasion` | Detect encoded/obfuscated secrets |
| `benign` | Labels benign traffic used for false-positive testing; it doesn't enable or select cases. |
| `a2a_scan` | Detect attacks in A2A messages |
| `a2a_card_poison` | Detect poisoned A2A Agent Cards |
| `operation_policy` | Enforce method-aware policy on allowlisted hosts (for example, fetch-only registries refuse writes) |
| `websocket_dlp` | Detect secrets in WebSocket frames |
| `ssrf_bypass` | Detect alternate SSRF encodings and IP forms |
| `shell_obfuscation` | Detect obfuscated shell commands |
| `crypto_dlp` | Detect cryptocurrency, wallet, or financial material |
| `hostname_exfil` | Detect exfiltration encoded into hostnames |
| `denial_of_wallet` | Detect resource-abuse sequences that exceed a declared tool-call count budget |

Only claim what your tool actually does; these labels help readers interpret results.

### `capability_registry` object

Copy the exact `id`, `format`, `revision`, and `sha256` from the registry
snapshot you use. The SHA-256 is over the raw snapshot file, not re-serialized
JSON. The runner rejects an unknown label, missing snapshot, digest mismatch,
duplicate label, or unsupported format before it emits any score. Keep that raw
snapshot with every published profile and result.

## Step 2: Write the runner

Copy the skeleton script and fill in the TODOs:

```bash
cp skeleton.sh ../your-tool/run.sh
cp tool-profile-template.json ../your-tool/tool-profile.json
```

The skeleton handles:
- Reading the tool profile
- Declaring delivery routes and result-state proof
- A starting loop for single-file JSON cases; complete logical-case discovery and multi-file temporal execution still need implementation.
- Emitting JSONL results
- Printing a summary

You fill in:
- Starting your tool
- Feeding each case to your tool
- Observing whether your tool blocked or allowed the traffic

### The three parts you must implement

Look for `TODO` markers in `skeleton.sh`. There are three:

1. **Start your tool.** Launch your proxy/service, wait for it to be ready.
2. **Prove the route.** For every case, establish exact delivery and a request-correlated verdict. If no exact route exists, emit `unreachable`; do not emit N/A from a declaration.
3. **Feed and observe.** Send the case payload to your tool and determine the verdict.

The Go runner can start managed commands and pass runner-owned fixture addresses
through environment variables. The full managed-command contract is documented
in [docs/RUNNER.md](../../docs/RUNNER.md#managed-command-hooks).

## Step 3: Handle each transport

### Fetch endpoint cases (`fetch_proxy`)

`fetch_proxy` cases are for tools that expose a fetch-style endpoint. The
built-in proxy adapter calls `/fetch?url=...` on the configured proxy address
using the method, body, and headers from the case payload. These cases exercise
URL, request-body, header, response-content, and some blocklist or SSRF checks
when the runner can express the case through that endpoint.

The pattern is:

1. Start your tool on a local port
2. For each case, build the request expected by your fetch endpoint
3. Send it to your tool's fetch endpoint
4. Check the response status code and body for the tool's block signal

### CONNECT forward-proxy cases (`http_proxy`)

`http_proxy` cases are for CONNECT-capable forward proxies. The runner drives
these by configuring the tool as an HTTPS proxy and sending requests to
runner-managed fixtures. These cases exercise forward-proxy and TLS-intercepted
request/response paths. A reverse proxy or API gateway is not equivalent to this
shape because the runner cannot currently rewrite arbitrary case URLs into a
fixed upstream route.

The pattern is:

1. Start your forward proxy on a local port
2. Configure the client request to use that port as the HTTPS proxy
3. Send the case payload through the proxy to the runner fixture
4. Check the proxy response status code and body for the tool's block signal

Use the [observable verdict rules](../../docs/RUNNER.md#observable-verdict-rules). A status code, missing response or nonzero process exit alone doesn't prove a security decision. An observed allow requires exact delivery and the applicable upstream proof. An observed block requires the surface's attributable denial or withholding proof. A missing route is `unreachable`; missing delivery or verdict proof is an error in active result output. Transport and process failures remain errors.

### MCP cases (mcp_stdio, mcp_http)

MCP cases provide `jsonrpc_messages` in the payload. Each message is a JSON-RPC 2.0 object. To test:

1. Start your tool in MCP proxy mode
2. Feed each JSON-RPC message through the proxy (write to stdin, read from stdout for stdio mode)
3. Check if the message was forwarded, modified, or blocked

Use the same surface-specific observation rules for MCP. A generic protocol error or process exit alone doesn't establish a security denial.

### Response scanning cases

Response cases (`input_type: response_content`) include a `response_body` in the payload. These are harder to test because you need to simulate a server returning that content. Options:

- Start a local HTTP server that returns the `response_body`
- Use a tool-specific runner only if it can prove the case exercised the declared transport
- Emit `unreachable` until an exact delivery route exists

### Cases you cannot handle

If your runner does not support a transport or input type, emit `unreachable`
with route evidence. This is an explicit coverage gap, not a scored error or
N/A. A narrow runner can support one transport while still reporting the rest
honestly.

Do not fake results. If you cannot observe the verdict, say so.

## Step 4: Validate your output

### Check JSONL format

Build the validator from the same benchmark revision and validate the profile and result rows against the canonical case metadata:

```bash
(cd ../../validate && go build -o aeb-validate .)
../../validate/aeb-validate profile tool-profile.json
../../validate/aeb-validate results results.jsonl ../../cases
```

Run these commands from `examples/your-tool/`. The validator checks the active artifact versions, registry reference, allowed result states and case-bound scoring rules. Active result rows use `block`, `allow`, `unreachable` or `error` as the observed verdict and `pass`, `fail` or `error` as the score. Budget-block cases additionally require the documented timing evidence; matching binary verdicts alone don't establish a pass.

### Check case coverage

Emit exactly one result for each logical case in the pinned source catalog, subject to any governed active-set selection. A temporal MCP drift directory is one case; its component JSON files aren't additional cases. Use the Go runner's logical loaders and `cases/MANIFEST.txt` as the discovery reference, and verify IDs as well as counts. The shell skeleton's raw JSON loop is incomplete for a full-corpus runner and must be replaced before publishing a full-corpus result. `make stats` reports loader-backed corpus counts.

## Common mistakes

**Treating claims as proof.** A reporting label never proves a route. Validate
it against the profile's retained registry snapshot, then add delivery and
verdict observation before scoring.

**Hardcoding verdicts.** Every verdict must come from observing your tool's actual behavior. If you return `block` without sending the request through your tool, the result is meaningless.

**Mixing stdout and stderr.** JSONL goes to stdout. Status messages, progress, and summaries go to stderr. If you print status to stdout, the JSONL will be unparseable.

**Forgetting false-positive coverage.** Benign cases need the same delivery and
verdict proof as attacks. A profile declaration cannot remove them from scope.

## Reference

- [docs/RUNNER.md](../../docs/RUNNER.md): the formal runner contract
- [docs/SPEC.md](../../docs/SPEC.md): case schema and field definitions
- [docs/gauntlet.md](../../docs/gauntlet.md): result states and scoring method
- [examples/pipelock/](../pipelock/): reference runner implementation
