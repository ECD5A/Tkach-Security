# Tkach Security Integration Guide

This is the current developer-facing integration model and Quickstart. It
describes the smallest safe composition available in v0.1. It is not a hosted
service or public internet gateway; the thin language carriers are documented
under `sdk/`.

## Quickstart

Run the compilable Basic example offline:

```text
cargo run -p tkach-gateway --example quickstart --locked
```

The example at
[`crates/tkach-gateway/examples/quickstart.rs`](../crates/tkach-gateway/examples/quickstart.rs)
constructs typed `Destination`, `FlowRule`, `Ruslo`, `Policy`, `Krosna`, and
bounded `Zaslon` values; wires a `Gateway` to a protected executor; submits a
bounded `ExternalRequest`; runs a deterministic provider; and releases output
only from a successful `GatewayResult`.

## CLI onboarding

The workspace also includes a deliberately small local onboarding adapter. From
the repository root, install its binary and create a starter request:

```text
cargo install --path crates/tkach-cli --locked
tkach init my-agent
tkach check my-agent/.tkach/request.json
tkach run --demo
```

`tkach init [DIRECTORY]` creates `.tkach/request.json` with a bounded example;
it contains no credentials, refuses to overwrite an existing starter, and
rejects a pre-existing `.tkach` symlink, junction, or non-directory.
`tkach doctor` inspects the local directory, starter request, loopback address,
and whether a bearer token is configured without printing the token. It does
not connect a model, authorize an action, or start a server. `tkach check
[REQUEST_JSON]` caps the file read at the Gateway's request bound and
uses the same strict `ExternalRequest` parser. `tkach run --demo` executes the
existing deterministic Gateway proof with a fake broker and no network or real
side effect. `tkach --lang ru --help` or `TKACH_LANG=ru` selects the localized
help and result messages. Bare `tkach` in a terminal or `tkach ui` opens
an interactive menu: Up/Down or 1–8 selects, Enter confirms, Esc goes back.
F1 and l/L/д/Д switch languages; in path fields only F1 switches, so filenames
remain editable. Path input is bounded to 256 UTF-8 bytes and never evaluated
as a shell command. Results wrap and scroll with Up/Down. The terminal restores
its screen, cursor and input mode on normal exit and returned errors.
The menu requires at least 44 columns and 18 rows. `NO_COLOR` disables selection
color. If raw terminal mode is unavailable, the CLI falls back to the same
line-oriented menu contract. Validation accepts regular files only and runs on
one background reader.
Settings change only the current session language and color preference. They do
not edit policy, authority, secrets, network binding, or provider configuration.
Esc cancels waiting and discards its eventual result; a stalled OS read can
remain until process exit, and another reader cannot start while it is pending.
Pipes retain bounded line commands, including `/l en` and `/l ru`.
The interactive menu is a responsive Ratatui panel with a selected action,
local status panel, keyboard footer, and the supplied dense Unicode block-art
banner. The banner is embedded directly in `tkach-cli`; it is not read from a
runtime asset and no download or installation occurs. It occupies 113 columns
and 11 rows. `TKACH_BANNER=compact` hides it, while `TKACH_BANNER=png` selects
the supplied PNG pixel renderer. Small terminals use the compact header. The
block-art path avoids Braille glyphs, but the terminal emulator still owns
font and code-page rendering; the CLI owns layout, borders, and colors.
CLI is an optional local onboarding tool. Creating a starter request does not
deploy a policy or grant authority. `tkach serve --demo` is a separate,
deterministic reference runtime for local HTTP smoke tests; it is not a
protection daemon or a production gateway. Applications integrate through the
Gateway library or a separately reviewed HTTP/MCP runtime.

## HTTP adapter contract — v0.1

`tkach-http` is a thin language-neutral carrier around an existing
`tkach_gateway::RuntimeService<P>`. The crate remains a library adapter: a
trusted host supplies the existing Gateway, provider, executor, and runtime
authenticator; HTTP never gets direct access to those internals. The CLI also
offers `serve --demo`, but that command wires only the deterministic demo
Gateway and exists for local integration smoke tests.

The v0.1 listener is intentionally local and sequential:

- `HttpListener::bind` accepts only an IP loopback address, including an
  ephemeral port for tests; `0.0.0.0`, LAN addresses, DNS binding, and public
  internet serving are rejected;
- `GET /healthz` returns the static `{"status":"ok"}` liveness document and
  does not authorize or execute anything;
- `POST /v1/run` requires HTTP/1.1, one non-empty `Host`, exact
  `Content-Type: application/json`, decimal `Content-Length` within
  `MAX_HTTP_BODY_BYTES`, and `Authorization: Bearer <token>`;
- `Transfer-Encoding`, chunked framing, redirects, compression, keep-alive,
  and query/path normalization are unsupported and fail closed;
- the JSON body is exactly `{request_id, lifecycle_id, request}`. Unknown or
  duplicate fields are rejected; `request` remains raw until the existing
  runtime service applies its strict Gateway parser. The adapter translates the
  header token into the runtime frame and never returns it;
- each connection receives one bounded JSON response and then closes. Runtime
  `Success`, `Denied`, `Replay`, provider, effect, and invalid-request outcomes
  retain explicit HTTP status classes and the payload-free `RuntimeResponse`
  body. No model/provider payload is turned into an HTTP error message.
- header and body reads share a fixed 500 ms exchange deadline in addition to
  byte ceilings, so a slow client cannot hold the sequential listener forever.

This contract is suitable for a local trusted host and language clients that
can issue ordinary HTTP/1.1 requests. It is not TLS, process/OS isolation,
durable replay, cancellation-on-disconnect, a public gateway, or a replacement
for the Core/Gateway authority model. The Rust client below is a thin reviewed
carrier. The reference CLI server is loopback-only, sequential, bearer-
authenticated, and deterministic; it must not be exposed as a public service.
MCP, other-language SDKs, and a distributable production server require
separate review.

### Local HTTP runtime

The CLI has two deliberately separate server modes. The deterministic smoke
runtime does not call a provider:

```text
TKACH_BEARER_TOKEN=local-development-secret \
TKACH_HTTP_ADDR=127.0.0.1:8080 \
tkach serve --demo
```

On PowerShell, set the same variables with `$env:TKACH_BEARER_TOKEN` and
`$env:TKACH_HTTP_ADDR` before starting the command. The address must parse as a
loopback `SocketAddr`; DNS names, LAN addresses, and wildcard binds are
rejected. `/healthz` is unauthenticated liveness only. `/v1/run` requires the
configured bearer token and is backed by the deterministic bounded demo
provider, so it performs no real model call or protected side effect. The
process handles one bounded request per connection and stops with Ctrl-C.

The ordinary `tkach serve` command starts the local provider runtime. It uses
the reviewed non-streaming OpenAI Responses adapter (or a trusted endpoint
with the same OpenAI-compatible wire contract), while keeping the provider
outside Core:

```text
TKACH_BEARER_TOKEN=local-development-secret \
OPENAI_API_KEY=trusted-provider-secret \
OPENAI_MODEL=gpt-4.1-mini \
TKACH_HTTP_ADDR=127.0.0.1:8080 \
tkach serve
```

`OPENAI_BASE_URL` may select a trusted HTTPS OpenAI-compatible endpoint. The
default server profile is read-only: protected model-proposed effects are
denied by policy and by a defense-in-depth executor, so this command is a
local provider runtime, not a generic production executor. The bearer token
and provider credential are environment configuration only; neither is
accepted in request JSON, MCP arguments, or command-line arguments. `/healthz`
is unauthenticated liveness, `/v1/run` is bearer-authenticated, and Ctrl-C
requests a bounded stop between connections.

Any language can use the same HTTP contract directly. The health route is
unauthenticated liveness; the run route requires the trusted bearer proof:

~~~text
curl --fail http://127.0.0.1:8080/healthz
curl --fail --silent --show-error \
  -H 'Authorization: Bearer <trusted-runtime-token>' \
  -H 'Content-Type: application/json' \
  --data '{"request_id":"request-1","lifecycle_id":"lifecycle-1","request":{"messages":[{"role":"user","content":"hello"}],"metadata":[],"tool_declarations":[]}}' \
  http://127.0.0.1:8080/v1/run
~~~

The placeholder token must be supplied by trusted host configuration. Do not
put it in model-controlled request data, shell history, or committed examples.

### Private OCI image

The repository includes a multi-stage `Dockerfile` for a local/private image.
It contains only the `tkach` CLI, runs as UID 10001, defaults to the same
loopback address, and uses `tkach health` for the bounded container
healthcheck:

```text
docker build -t tkach:local .
docker run --rm --network host \\
  -e TKACH_BEARER_TOKEN=local-development-secret \\
  -e OPENAI_API_KEY=trusted-provider-secret \\
  tkach:local serve
```

Host networking is the explicit Linux host-local deployment profile. The image
does not enable wildcard binding, TLS termination, a proxy, or a public
network service. A bridge/ingress deployment needs a separate reviewed
authenticated boundary before it can be documented as supported.

## Rust client adapter — v0.1

tkach-client is an optional typed Rust client for the HTTP contract. It
accepts only a loopback SocketAddr, validates the bearer token before any
connection, validates the inner request with ExternalRequest, bounds the HTTP
envelope and response, rejects ambiguous response framing, and zeroizes its
owned token and request-header buffer. It does not retry, interpret policy,
create authority, or expose a non-loopback transport.

Add the local crate while the project is still using the workspace:

~~~text
tkach-client = { path = "../tkach-client", version = "0.1.0" }
~~~

The smallest call path is:

~~~rust
use std::net::SocketAddr;
use tkach_client::{RunRequest, TkachClient};

let client = TkachClient::new(
    "127.0.0.1:8080".parse::<SocketAddr>()?,
    "trusted-runtime-token",
)?;
client.health()?;
let request = RunRequest::new(
    "request-1",
    "lifecycle-1",
    br#"{"messages":[{"role":"user","content":"hello"}]}"#.to_vec(),
)?;
let response = client.run(&request)?;
~~~

ClientResponse status_code, body, and is_success are transport observations
only. A non-2xx response is not a reason to retry an effect or to treat
model/provider output as trusted. The client is local-only: it is not TLS,
process isolation, a public service, or an SDK for other languages. Those
languages can use the same strict HTTP contract directly.

## Language SDKs — v0.1

The Python, Node.js/TypeScript, and Go clients are thin carriers for the same
local HTTP contract. They accept numeric loopback IPs only, bound request and
response framing, reject ambiguous/chunked/oversized responses, and never
retry effects. Responses are transport observations; policy and authority stay
inside the Rust runtime.

Installation and usage live with each adapter:

- [Python](../sdk/python/README.md): standard-library runtime and local wheel.
- [JavaScript / TypeScript](../sdk/javascript/README.md): dependency-free Node
  runtime, TypeScript declarations, and local npm package.
- [Go](../sdk/go/README.md): dependency-free local module.

See [Distribution](DISTRIBUTION.md#external-publication-status) for publication
status and [Contributing](../CONTRIBUTING.md#required-checks) for validation.
These clients do not provide TLS, process isolation, policy, or secret brokering.

## MCP stdio adapter — v0.1

tkach-mcp is a separate protocol adapter over tkach-client. It implements the
official [MCP 2025-06-18 stdio shape](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports):
newline-delimited UTF-8 JSON-RPC,
initialize/initialized lifecycle, ping, tools/list, and tools/call. It exposes
one tool named tkach_run. The tool accepts request_id, lifecycle_id, and a
strict Tkach Gateway request object; the adapter delegates the call exactly
once to the configured local HTTP client.

The adapter keeps MCP protocol data outside Core. It does not accept authority,
Propusk, executor, broker, provider, or raw credentials as tool arguments.
JSON-RPC IDs, input lines, arguments, and emitted responses are bounded;
malformed messages and unknown fields fail closed; tool failures are returned
inside an MCP tool result with a static diagnostic. stdout contains only
newline-delimited JSON-RPC messages; diagnostics belong on stderr.

The binary reads TKACH_HTTP_ADDR (default 127.0.0.1:8080) and the required
TKACH_BEARER_TOKEN environment variable. Tokens are never accepted on command
line arguments. The process must be paired with a separately configured local
tkach-http listener:

~~~text
TKACH_HTTP_ADDR=127.0.0.1:8080
TKACH_BEARER_TOKEN=trusted-runtime-token
tkach-mcp
~~~

After the matching `tkach-mcp` version is published to crates.io, an MCP host
can launch it as a stdio server. For example, a Claude-compatible host config
uses the adapter command and trusted environment values (replace the token
through the host's secret-management mechanism; do not commit a real token):

~~~json
{
  "mcpServers": {
    "tkach": {
      "command": "tkach-mcp",
      "env": {
        "TKACH_HTTP_ADDR": "127.0.0.1:8080",
        "TKACH_BEARER_TOKEN": "<trusted-runtime-token>"
      }
    }
  }
}
~~~

The adapter is intentionally not a standalone model provider: start
`tkach serve` in the trusted local host first. A host that cannot keep the
token outside model-controlled data must not enable this integration.

For diagnostics, `tkach-mcp --version` and `tkach-mcp --help` do not read
credentials or connect to the runtime. Any other argument is rejected before
environment configuration; normal operation uses no arguments and stdio.

This is stdio only. It is not Streamable HTTP, TLS, process isolation, a
public service, a replacement for human consent in the MCP host, or an Official
MCP Registry publication. The host remains responsible for consent and for
protecting its environment and subprocess.

## Public API contract — v0.1

The supported Rust integration points are deliberately split by trust boundary:

- `tkach-core` is the provider- and protocol-independent security kernel. Use
  its typed domain, Krosna/Ruslo/Zaslon decisions, Niti/Metka state, Propusk,
  Klyuchnik, and Sled APIs; do not treat serialized values as authority.
- `tkach-gateway` is the bounded orchestration boundary. Its supported entry
  points are `ExternalRequest`, `Gateway`, `Provider`, `ProtectedExecutor`,
  `RuntimeService`, and the narrow `RealEffectExecutor` profile.
- `tkach-provider-openai` is an optional thin provider adapter. Its output is
  hostile provider DATA and raw proposals only; it is never a policy or
  execution API.

The security contract is stable across these packages: model/provider output
cannot mint authority; protected effects require exact `Propusk`; final
Ruslo/Zaslon checks remain mandatory; bounds and fail-closed errors are part of
the behavior. Private fields, module layout, test doubles, and diagnostic text
are not compatibility contracts.

The accepted external request schema is strict bounded JSON. The optional local
runtime schema is a four-byte big-endian length followed by one strict JSON
frame containing `request_id`, `lifecycle_id`, `auth`, and `request`; it has no
version negotiation and must be used by a client pinned to a compatible v0.1
release. A future public API version must add explicit negotiation before
cross-release runtime interoperability is promised.

Compatibility follows the [version policy](DISTRIBUTION.md#version-and-package-contract).
There is intentionally no umbrella `tkach` facade yet: introducing one is a later DX
decision, not permission to duplicate Core or Gateway logic.

## What an existing AI agent changes

Replace the direct path

`model -> application tool/executor -> side effect`

with

`external request -> Gateway -> Provider -> typed proposal -> Krosna/Ruslo/Zaslon -> ProtectedExecutor`.

The host constructs a `Gateway` with trusted `Krosna`, ingress/egress
`Zaslon`, a valid release `Destination`, and an executor that accepts only
`Propusk`. The application either calls `Gateway::run` with a validated
`ExternalRequest` or `Gateway::run_json` with a bounded JSON body.

For a local runtime boundary, the application may instead place the Gateway
and provider behind `RuntimeService` and `RuntimeListener`. The listener uses
loopback-only length-prefixed frames and trusted bearer-proof authentication;
the proof identifies the caller but never becomes a Krosna capability. The
service owns bounded request/lifecycle replay state and a sequential admission
path. It is suitable as a local architecture proof and requires separately
reviewed TLS/IPC, OS/process isolation, and durable replay for stronger
deployment profiles.

The provider receives only bounded `ProviderRequest` DATA and the fixed trusted
tool vocabulary. It never receives the executor, broker, `Propusk`, `Decision`,
or release function.

## Minimum integration steps

1. Install/use the `tkach-core` and `tkach-gateway` Rust crates in the host
   process, or use `tkach-client` against a separately configured local HTTP
   listener. The client is an adapter, not a package-wide facade.
2. Convert external messages into `ExternalRequest`; use `ExternalRole::Data`
   for imported documents, web text, and other attacker-influenced material.
3. Define capabilities as typed `ActionRequest` shapes and Krosna policy rules;
   do not authorize arbitrary model-provided strings.
4. Declare protected destinations explicitly as `Destination::Internal`,
   `Destination::PublicExternal`, or `Destination::SecretBroker` and configure
   Ruslo rules independently from action policy.
5. Route every tool implementation through `ProtectedExecutor`; never expose a
   raw executor or raw action request to the provider.
6. Keep credentials in trusted host configuration. Use Klyuchnik handles and
   broker-side use for secrets; never copy raw values into `ModelInput`.
7. Treat `GatewayError::kind()` and its payload-free `SledTrace` as the DENY
   reason surface. Do not turn model text into an authorization explanation.
8. Release `GatewayResult::output()` only after the Gateway returns success.

### Denial and continuation semantics

A denied action, failed final gate, malformed provider turn, timeout, or
cancellation is terminal for that `Gateway::run` lifecycle. The provider is not
silently resumed and staged output/effects are not released. An application may
start a new explicitly bounded run with a new request and provider if its own
workflow permits that choice; this is a new lifecycle, not a continuation that
inherits denied authority or staged state.

## Capability and destination model

`RuntimeService` and `RuntimeListener` are orchestration/transport boundaries,
not a new security primitive. They authenticate and bound a caller lifecycle;
Krosna, Propusk, Ruslo, Zaslon, Gnezdo, Niti, Metka, Klyuchnik, and Sled keep
their existing authority, flow, lineage, secret, and evidence roles.

An integrator needs to understand four operational concepts:

- `Propusk` — scoped execution capability issued only by Krosna;
- `Ruslo` — directional information-flow decision;
- `Zaslon` — formal content/action hard boundary;
- `Klyuchnik` — broker-side secret-use isolation.

`Gnezdo`, `Niti`, and `Metka` are the data/control and lineage state carried by
the system; `Sled` is the safe diagnostic evidence. The model does not need to
construct or mutate these values directly.

## Credential placement

- OpenAI credentials belong in `OpenAiConfig`/trusted environment and are
  consumed only by the adapter transport.
- Application secrets belong behind a `SecretBroker` implementation and are
  represented to model-facing code only by `SecretHandle` values or
  payload-free receipts.
- No credential belongs in metadata, external message content, provider tool
  arguments, logs, debug output, or `GatewayResult` text.

## Deployment profiles

### Basic Gateway

**Use:** model input containment, bounded provider lifecycle, final content and
flow checks, and safe DENY evidence without authorizing real effects.

**Setup:** trusted Krosna/Zaslon/Ruslo configuration and a rejecting or
non-effect executor; all model I/O still passes through Gateway.

**Guarantees:** bounded ingress, Gnezdo DATA containment, provider staging,
Zaslon/Ruslo final gates, no model-minted authority.

**Unavailable:** no guarantee for effects performed by application code outside
the Gateway; no secret isolation unless Klyuchnik is used; no business-intent
validation.

### Controlled Agent

**Use:** tools and protected effects controlled by Tkach.

**Setup:** Basic Gateway plus explicit Krosna action policy, Ruslo flow policy,
and a `ProtectedExecutor` implementation that refuses raw requests.

**Guarantees:** Basic guarantees plus exact-scope Propusk authorization,
preflighted action batches, protected lifecycle/effect ordering, directional
export control, and typed tool-result lineage.

**Unavailable:** raw credentials may still leak if the host bypasses Klyuchnik;
generic executor side effects, transaction semantics, and concurrent path-race
guarantees remain the integrator's responsibility. The repository's narrow
`RealEffectExecutor` contract is included in the Local Effect Boundary section
below; this file is the single integration reference.

### Sealed Agent

**Use:** maximum current boundary for sensitive data and tools.

**Setup:** Controlled Agent plus Klyuchnik-backed `SecretBroker`, no raw secret in
model context, no out-of-band executor/broker/release path, and trusted host
configuration isolated from model-controlled data.

**Guarantees:** Controlled guarantees plus broker-held secret isolation,
reveal denial, exact secret-use routing, and payload-free receipts.

**Unavailable:** protection from a fully compromised host/OS, deliberate
application bypasses, semantic prompt injection, durable distributed replay,
or production transaction guarantees.

### Local Effect Boundary

**Use:** the reviewed local reference executor for integration tests and
single-host deployments that accept its narrow contract.

**Setup:** trusted `RealEffectExecutor` configuration with an existing ordinary
sandbox root and an explicit loopback endpoint, plus the same Krosna/Ruslo/
Gateway wiring as Controlled Agent.

**Guarantees:** only exact `workspace/input.txt` read,
create-only `workspace/output.txt` write, and fixed-payload loopback HTTP are
reachable; model-selected paths, destinations, endpoints, and payloads are not
interpreted. Successful effects return bounded receipts; post-attempt failures
are reported as unknown.

**Unavailable:** arbitrary filesystem/network operations, overwrite or
rollback semantics, durable distributed replay, and elimination of every
concurrent path-substitution race. This profile must not be presented as a
general production gateway.

### Local Authenticated Runtime

**Use:** a loopback caller needs a bounded, authenticated entry point into a
trusted Gateway lifecycle.

**Setup:** `RuntimeAuthenticator` is constructed from trusted deployment
configuration; `RuntimeListener` binds to loopback; the caller sends one
bounded length-prefixed JSON frame with request and lifecycle identity.

**Guarantees:** malformed/oversized frames, invalid authentication, duplicate
identities, shutdown, and cancellation fail closed before a protected effect;
valid authentication still requires ordinary Gateway/Krosna/Ruslo/Zaslon
authorization. Runtime receipts are payload-free evidence and an unknown
effect outcome is terminal.

**Unavailable:** TLS, OS identity/process isolation, durable cross-restart or
distributed replay, forceful interruption of synchronous calls, and protection
from a same-privilege out-of-band executor.

## Secure defaults

The common safe case is: bounded JSON, `ExternalRole::Data` for imported text,
default-deny policy, no external export of protected-derived values, no raw
credential input, and final Gateway-only release. Advanced policy and endpoint
customization remain possible through typed Rust APIs; the current source
surface adds no configuration DSL.
