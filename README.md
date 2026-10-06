# TrustGuard Guardrail for MuleSoft Flex Gateway

A custom [Flex/Omni Gateway policy](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview) (built with the MuleSoft Policy Development Kit, in Rust/WebAssembly) that integrates **MuleSoft Anypoint Platform** with **NeuralTrust TrustGuard**.

It's meant to be applied to **LLM** and **MCP** endpoints (Flex Gateway / Omni Gateway) and evaluates prompts and model responses (and MCP tool calls and their results) against TrustGuard, so TrustGuard's guardrails (jailbreak detection, PII/DLP, prompt injection, etc.) apply to traffic flowing through MuleSoft. In `enforce` mode it does so **before** the traffic reaches the LLM provider or the client and applies TrustGuard's verdict; in `mirror` mode (the default) it never modifies traffic and only sends TrustGuard a copy for monitoring — see [Modes](#modes-mirror-default-and-enforce).

## How it works

The policy calls the **TrustGuard Evaluate API** (`POST {trustguardUrl}/v1/evaluate`) at two points in the request lifecycle:

| Phase | When | What gets sent |
|---|---|---|
| `direction: "input"` | Before the client's prompt (or MCP `tools/call`) is forwarded upstream | `protocol: "llm"` — the extracted `messages`/`tools` (see below); or `protocol: "mcp"` — the `tools/call` JSON-RPC envelope |
| `direction: "output"` | Before the model's response (or MCP tool result) is returned to the client | `protocol: "llm"` — the response wrapped as a synthetic `assistant` message; or `protocol: "mcp"` — the JSON-RPC result envelope |

In `enforce` mode, TrustGuard's verdict (`status`) drives what the policy does next:

| `status` | Action |
|---|---|
| `allow` / `report` | Traffic passes through unchanged |
| `block` | **Input:** the request is rejected with a `403` and never reaches the model. **Output:** the response body is replaced with an `{"error": ...}` JSON so it never reaches the client, but the response keeps the upstream's status code (typically `200`). MCP responses delivered as SSE get a JSON-RPC error event instead (see [MCP](#mcp-protocol-mcp)) |
| `transform` | The body is rewritten with TrustGuard's `transformed_payload` (e.g. masked PII) before continuing |
| `ask` (input only) | Configurable — the gateway has no interactive UI, so `askBehavior` decides `block` or `allow` |

If TrustGuard itself is unreachable or errors out, `failMode` decides whether to fail closed (block, safer) or open (let traffic through).

### Modes: `mirror` (default) and `enforce`

| Mode | What happens |
|---|---|
| `mirror` (default) | Every request and response is forwarded **unmodified**, without waiting for TrustGuard; responses — streams included — go through to the client chunk by chunk as they arrive. A copy is sent to TrustGuard fire-and-forget (for a response, once it has ended), so it adds no latency. TrustGuard's verdict is never applied — nothing is blocked or masked — and findings are only visible in TrustGuard's own Activity log. `failMode`, `askBehavior` and a `block` setting in `unrecognizedRequestFormat`/`unrecognizedResponseFormat` have no effect in this mode. |
| `enforce` | Each request/response is evaluated **before** it's forwarded, and the verdict is applied as described above. |

Use `mirror` to observe what TrustGuard would flag on real traffic before switching to `enforce`.

For where to place it in the API's policy chain, see [Policy order in the chain](DEPLOYMENT.md#policy-order-in-the-chain).

### LLM providers understood structurally (`protocol: "llm"`)

The policy recognizes every common LLM provider wire format and normalizes it to the same canonical `{"messages":[...], "tools":[...]}` shape before calling TrustGuard, regardless of which one matched: **OpenAI Chat Completions** (and its wire-compatible siblings Azure/Groq/DeepSeek/XAI/Cerebras/OpenRouter/Mistral), **Anthropic Messages**, **Google Gemini/Vertex**, **AWS Bedrock** (Converse API), the **OpenAI Responses API**, and **Cohere**. A `transform` (DLP masking) verdict is spliced back into the *native* body at the exact field it came from, so tool-call blocks in the same message (e.g. Anthropic `tool_use`, Bedrock `toolUse`) are left untouched by a rewrite that only touches text.

### MCP (`protocol: "mcp"`)

An MCP `tools/call` request (`{"jsonrpc":"2.0","method":"tools/call","params":{"name","arguments"}}`) is evaluated with the tool name and every string argument leaf flattened for scanning, and its `CallToolResult`/`tools/list` response likewise (text content blocks, `structuredContent` leaves, or the listed tool descriptions for `indirect_prompt_injection`). Every other JSON-RPC method (`initialize`, `resources/*`, `prompts/*`, MCP's own `tools/list` *request*, ...) is **not** evaluated at all, in either direction — only `tools/call` and its result carry content worth scanning. The one exception is a non-empty `tools/list` *result*, which is evaluated (structurally) so `indirect_prompt_injection` can score the listed tool descriptions. A JSON-RPC body that isn't MCP goes through the fallback described below.

A `transform` verdict is applied from the envelope TrustGuard echoes back for `protocol: "mcp"`: the masked `params.arguments` (request) or the masked `result` (response) is taken whole, so masking inside content the text extraction doesn't model — such as an embedded `resource` block's text — is applied too. If no envelope comes back, the masked text is mapped back onto the inspected values; if that doesn't line up either, the request/response is blocked rather than forwarded unmasked. The tool name is never rewritten by a transform.

Responses are handled the same way whether the MCP server returns plain JSON or **Server-Sent Events** (`text/event-stream`, as MCP's Streamable HTTP transport does — e.g. GitHub's remote MCP server). For SSE, the policy evaluates the JSON-RPC response carried in the event's `data:` line:

- `transform`: the masked values are written back into that event; the rest of the stream is left as-is.
- `block`: the stream is replaced by a single SSE event with a JSON-RPC error for the same request id (`{"jsonrpc":"2.0","id":...,"error":{"code":-32001,"message":"blocked by trustguard policy"}}`), so the MCP client still receives a reply it can parse.

Other events in the stream (e.g. progress notifications) are not evaluated.

### Bodies the policy doesn't recognize

A body that doesn't match any of the LLM or MCP shapes above falls back to `unrecognizedRequestFormat`/`unrecognizedResponseFormat` (`analyze` by default): the **raw payload is sent to TrustGuard as plain text**, so its content is still evaluated. A `transform` verdict is treated as `block` in this mode, since the policy can't safely rewrite a body whose structure it doesn't understand.

### Streaming and WebSocket traffic — limitations

In `enforce` mode, evaluating a response means having all of it before it's forwarded — that's the only way to block or mask it before the client sees it. For a streamed LLM response that would turn token-by-token delivery into a single burst at the end, so streamed output is **never blocked or masked**, in either mode. Instead it's forwarded as it arrives and, once it has ended, its reassembled text is sent to TrustGuard **for audit only**: findings show up in TrustGuard's Activity log, but the verdict isn't applied (the client already has the response). `mirror` mode applies the same "forward as it arrives, evaluate the copy afterwards" approach to every response, since it never changes one anyway.

| Traffic | Input (request) | Output — `enforce` | Output — `mirror` |
|---|---|---|---|
| Non-streaming request/response | Evaluated | Evaluated before it's forwarded (unless `evaluateResponse: false`) | Forwarded as it arrives; copy evaluated when it ends |
| **Streaming** LLM request | Evaluated (can be blocked/transformed in `enforce`) | **Not enforced** — the stream reaches the client byte-for-byte; the reassembled text is sent to TrustGuard when it ends, for audit only | Same as `enforce`: forwarded as it arrives, audited when it ends |
| MCP `tools/call`/`tools/list` answered with SSE | Evaluated (`tools/call`) | Read in full and evaluated before it's forwarded | Forwarded as it arrives; copy evaluated when it ends |
| Any other SSE response (e.g. an MCP server's standalone `GET` notification stream) | Not evaluated | Read in full before it's forwarded (see below) | Forwarded as it arrives; not evaluated |
| **WebSocket** upgrade (`Connection: Upgrade` + `Upgrade: websocket`) | **Not evaluated** | **Not evaluated** — the connection is skipped entirely, since reading an upgraded connection's body would hang it | Same as `enforce` |

A request counts as streaming when any of these is true:

- The JSON body has `"stream": true` (OpenAI, Anthropic, OpenAI Responses, Cohere, ...).
- The path contains `:streamGenerateContent` (Gemini / Vertex).
- The path contains `/converse-stream` (AWS Bedrock Converse).

What this means in practice:

- In `enforce` mode, `evaluateResponse: true` does **not** protect streamed output: it's audited (TrustGuard logs what it finds), but never blocked or masked, and `failMode` doesn't apply to the audit copy, which is sent fire-and-forget. Any client that can send `"stream": true` (when the upstream accepts it) gets a response that hasn't been masked. If you need output guardrails, make sure the upstream/API doesn't allow streaming, or enforce that elsewhere in the policy chain.
- In `enforce` mode, an MCP `tools/call` answered with SSE is held until the server ends the stream (which it does after sending the result), so any progress notifications reach the client together with the result. A server that, in the middle of a tool call, sends the client a request over that stream and waits for the answer (e.g. `sampling` or `elicitation`) would not get it, and the call would hang until it times out.
- In `enforce` mode, a long-lived SSE response that isn't a streaming request as defined above — such as an MCP server's standalone `GET` notification stream — would not reach the client until the server closes it. `mirror` mode passes these through as they arrive.
- The streamed text sent for audit is reassembled for OpenAI Chat Completions and compatibles, Anthropic Messages, the OpenAI Responses API and Gemini (tool-call deltas aren't included); other stream formats, such as Cohere's or Bedrock's binary event stream, are forwarded but not audited. Copies (for the audit, and in `mirror` mode for any response) are capped at 4 MiB per response: a larger response is still forwarded in full, but not sent to TrustGuard.
- Responses to MCP protocol messages other than `tools/call`/`tools/list` are not read at all, in either mode.

## Quick start

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for the full, step-by-step guide: prerequisites, authentication, building, publishing to Exchange, applying the policy to an API in API Manager, and verifying it end to end — including real gotchas found while deploying this against a live Managed Omni Gateway (wrong plugin package names, CLI auth quirks with multi-region orgs, policy-apply validation rules, propagation delays, etc.).

## Configuration reference

| Property | Required | Default | Description |
|---|---|---|---|
| `trustguardUrl` | Yes | `https://trustguard.neuraltrust.ai` | Base URL of your TrustGuard instance |
| `apiKey` | Yes | — | TrustGuard collector API key (masked in the UI) |
| `consumerId` | No | — | Falls back automatically to the Exchange Asset ID of the API this policy is attached to |
| `providerName` | No | — | Falls back automatically to the `x-llm-proxy-llm-provider` request header when present |
| `sessionIdHeader` | No | — | Name of a request header carrying a session/conversation id, sent to TrustGuard as `session_id` (the `multiturn_guard` anchor). Tried first; see [Session id resolution](#session-id-resolution) below for the full fallback chain |
| `sessionIdBodyField` | No | — | Name of a top-level JSON field in the request body to read a session id from, if no header matched |
| `mode` | No | `mirror` | `mirror` forwards traffic unmodified and only sends TrustGuard a copy; `enforce` evaluates before forwarding and applies the verdict. See [Modes](#modes-mirror-default-and-enforce) |
| `evaluateResponse` | No | `true` | Set to `false` to only evaluate the request, not the model's response. Streamed (SSE) LLM responses are only ever audited after they've been delivered, never blocked or masked, in either mode; set this to `false` to skip that audit too. WebSocket connections are never evaluated — see [Streaming and WebSocket traffic](#streaming-and-websocket-traffic--limitations) |
| `timeoutMs` | No | `2000` | Timeout for calls to TrustGuard |
| `failMode` | No | `closed` | `closed` blocks on TrustGuard failure (recommended for production), `open` lets traffic through |
| `askBehavior` | No | `block` | How to handle an `ask` verdict on the request phase |
| `unrecognizedRequestFormat` | No | `analyze` | How to handle a request shape the policy can't parse (`block`, `allow`, or `analyze` — send the raw payload as text to TrustGuard). Applies to any body that isn't one of the supported LLM formats or MCP |
| `unrecognizedResponseFormat` | No | `analyze` | Response-side equivalent of `unrecognizedRequestFormat` |

Full details and rationale for each in [DEPLOYMENT.md](DEPLOYMENT.md#3-project-structure).

### Session id resolution

TrustGuard's `session_id` anchors the `multiturn_guard` detector (multi-turn jailbreak patterns). Resolved once per request, in this order:

1. The header named by `sessionIdHeader`, if configured.
2. A well-known header, tried in order: `X-Session-Id`, `X-OpenWebUI-Chat-Id` — not configurable, so you get this coverage for free without typing an exact header name.
3. The JSON body field named by `sessionIdBodyField`, if configured and steps 1–2 found nothing.
4. A freshly generated id, if nothing above matched anything — echoed back to the caller as `X-Session-Id` on the response, so it can send the same id on its next turn instead of starting a fresh, ungrouped session every time.

There is deliberately no `userIdHeader`/`userEmailHeader` equivalent for end-user identity (`attributes.user`). A caller-supplied header is fine for a low-stakes correlation id like `session_id` (worst case a forged one only confuses `multiturn_guard`'s turn-grouping), but not for an identity TrustGuard or an operator might use for per-user policy or audit decisions — trusting a raw client header for that would let a caller attribute its own traffic to someone else with nothing validating it. A trustworthy per-user identity signal would need to come from an authenticated principal resolved by the gateway's own auth layer; this policy, sitting as a generic HTTP proxy filter, has no such signal available to read.

---

## Make command reference
This project has a Makefile that includes different goals that assist the developer during the policy development lifecycle.

*For more information about the Makefile, see [Makefile](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-project#makefile).*

### Setup
The `make setup` goal installs the Policy Development Kit internal dependencies for the rest of the Makefile goals.

*For more information about `make setup`, see [Setup the PDK Build environment](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-project#setup-the-pdk-build-environment).*

### Set the organization
`make set-group-id GROUP_ID=<organization-id>` sets the Anypoint organization the policy is built and published under (`group_id` in `Cargo.toml`). It checks that the value is an organization ID (a UUID) before writing it. Run it once before building; every build checks it and stops with a clear message if it's still unset.

### Build asset files
The `make build-asset-files` goal generates all the policy asset files required to build, execute, and publish the policy. This command also updates the `config.rs` source code file with the latest configurations defined in the policy definition.

*For more information about creating a policy definition, see [Defining a Policy Schema Definition](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-schema-definition).*

*For more information about `make build-asset-files`, see [Compiling Custom Policies](https://docs.mulesoft.com/pdk/latest/policies-pdk-compile-policies).*

### Build
The `make build` goal compiles the WebAssembly binary of the policy. It requires `group_id` in `Cargo.toml` to be your Anypoint organization ID — set it first with `make set-group-id` (see [Set the organization](#set-the-organization)).
Since the source code must be in sync with the policy definition configurations, this goal runs the `build-asset-files` before compiling.

*For more information about `make build`, see [Compiling Custom Policies](https://docs.mulesoft.com/pdk/latest/policies-pdk-compile-policies).*

### Run
The `make run` goal provides a simple way to execute the current build of the policy in a Docker containerized environment. It uses two files in `playground/config`:
- `registration.yaml`: a Flex Gateway registration in disconnected (local) mode. If it isn't there, `make run` generates it automatically with Docker (`flexctl registration create --mode disconnected`). It's git-ignored, since it contains credentials for that local gateway.
- `api.yaml`: the API and policy configuration to run, updated with the desired policy settings. This file also supports adding other policies to be applied along the one being developed.

The `playground/config` directory can also contain other resource definitions, such as accessory services used by the policy (Eg. a remote authentication service).

*For more information about `make run`, see [Debugging Custom Policies Locally with PDK](https://docs.mulesoft.com/pdk/latest/policies-pdk-debug-local).*

> Note: local Docker testing may hit a known limitation with `service`-typed properties (like `trustguardUrl`) — see the troubleshooting table in [DEPLOYMENT.md](DEPLOYMENT.md) if `make run`/`make test` fails with an `unknown cluster` error. The integration tests in this repository run fine locally: they point `trustguardUrl` at a plain-HTTP mock.

### Test
The `make test` goal builds the policy and runs the unit tests (in `src/`) and the integration tests (`tests/requests.rs`). The integration tests require Docker: each one starts a local Flex Gateway with the policy, plus a mock backend that plays both the upstream API and TrustGuard. `tests/config/registration.yaml` is generated automatically on the first run (git-ignored). Run a single integration test with `make test TEST=<test_name>`, or only the unit tests, without Docker, with `cargo test --lib`.

*For more information about writing integration tests, see [Writing Integration Tests](https://docs.mulesoft.com/pdk/latest/policies-pdk-integration-tests).*

### Publish
The `make publish` goal publishes the policy asset in Anypoint Exchange, under the organization set in `Cargo.toml`'s `group_id` (see [DEPLOYMENT.md](DEPLOYMENT.md#4-build)).

Since the publish goal is intended to publish a policy asset in development, the _assetId_ and name published will explicitly say `dev`, and the versions published will include a timestamp at the end of the version. Eg.
- groupId: your configured organization id
- visible name: _{Your policy name} Dev_
- assetId: _{your-policy-asset-id}-dev_
- version: _{your-policy-version}-20230618115723_

*For more information about publishing policies, see [Uploading Custom Policies to Exchange](https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies).*

### Release
The `make release` goal also publishes the policy to Anypoint Exchange, but as a ready for production asset. In this case, the groupId, visible name, assetId and version will be the ones defined in the project.

*For more information about releasing policies, see [Uploading Custom Policies to Exchange](https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies).*

### Skipping unchanged definition publishes
Both `make publish` and `make release` accept the `SKIP_UNCHANGED_DEFINITION` variable (default `true`). When enabled, the definition is not republished if its content matches the version already published in Exchange; instead the implementation asset is published with its dependency pointing at that already-published definition version. Set `SKIP_UNCHANGED_DEFINITION=false` to always republish the definition:

```
make publish SKIP_UNCHANGED_DEFINITION=false
```


### Policy Examples

The PDK provides a set of example policy projects to get started creating policies and using the PDK features. To learn more about these examples see [Custom policy Examples](https://docs.mulesoft.com/pdk/latest/policies-pdk-policy-templates).
