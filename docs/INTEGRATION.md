# Tkach Security Integration Guide

This is the current developer-facing integration model and Quickstart. It
describes the smallest safe composition available in v0.1. It is not an SDK
or a public internet gateway.

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
   process. The current source surface has no SDK or package-manager facade;
   this is an integration fact, not a permanent ban.
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
