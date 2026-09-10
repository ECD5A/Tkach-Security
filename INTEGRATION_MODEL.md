# Tkach Security Integration Model

This is the current developer-facing integration model. It describes the
smallest safe composition available in v0.1; it is not an SDK and does not
define a production transport.

## What an existing AI agent changes

Replace the direct path

`model -> application tool/executor -> side effect`

with

`external request -> Gateway -> Provider -> typed proposal -> Krosna/Ruslo/Zaslon -> ProtectedExecutor`.

The host constructs a `Gateway` with trusted `Krosna`, ingress/egress
`Zaslon`, a valid release `Destination`, and an executor that accepts only
`Propusk`. The application either calls `Gateway::run` with a validated
`ExternalRequest` or `Gateway::run_json` with a bounded JSON body.

The provider receives only bounded `ProviderRequest` DATA and the fixed trusted
tool vocabulary. It never receives the executor, broker, `Propusk`, `Decision`,
or release function.

## Minimum integration steps

1. Install/use the `tkach-core` and `tkach-gateway` Rust crates in the host
   process. The current phase intentionally has no SDK or package-manager
   facade.
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

## Capability and destination model

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
the executor's external side effects and transaction semantics remain the
integrator's responsibility.

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

## Secure defaults

The common safe case is: bounded JSON, `ExternalRole::Data` for imported text,
default-deny policy, no external export of protected-derived values, no raw
credential input, and final Gateway-only release. Advanced policy and endpoint
customization remain possible through typed Rust APIs; this phase adds no new
configuration DSL.
