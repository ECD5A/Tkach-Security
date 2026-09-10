# Tkach Security Production Runtime Threat Model

Status: R0 design baseline for `production-runtime-v0.1`.

This document extends the earlier Strong Core, Gateway, provider, and local
effect threat models to the runtime boundary. It is a design and review
contract, not evidence that an unimplemented control already exists. The
authoritative runtime invariant is:

> A hostile model may propose arbitrary behavior, but a protected effect is
> physically reachable only through a Tkach-controlled, bounded, authenticated,
> and policy-authorized execution path.

## Scope and security zones

The production runtime path is intentionally narrow:

```text
Client
  -> bounded authenticated Transport
  -> Gateway lifecycle and request identity
  -> untrusted Provider/Model boundary
  -> Gateway staging
  -> Krosna + Ruslo + Zaslon
  -> Propusk
  -> Tkach-owned Executor / Klyuchnik
  -> fixed filesystem or network effect
  -> payload-free receipt and safe release
```

The arrows are trust boundaries. A provider response, transport claim, client
principal, receipt, or persisted identifier is data until the trusted runtime
has validated it. Authentication identifies the caller; it does not authorize
an effect and it never mints a `Propusk`.

### Assets

- Krosna policy, hard-deny rules, Ruslo flow rules, and Zaslon state.
- `Propusk` scope and its one-lifecycle execution authority.
- Protected filesystem contents, network destinations, and effect payloads.
- Klyuchnik-held secret bytes and the absence of those bytes from model,
  transport, logs, errors, receipts, debug output, and core dumps where the
  runtime can control the surface.
- Request/lifecycle identity, replay state, cancellation state, and bounded
  resource availability.
- Payload-free Sled evidence and effect receipts.

### Actors and capabilities

| Actor | Attacker capability | Security consequence if unchecked |
| --- | --- | --- |
| Client | Sends malformed, oversized, unauthenticated, replayed, concurrent, or cross-lifecycle requests. | Parser/resource exhaustion, identity confusion, or effect before authentication. |
| Authenticated client | Supplies valid authentication but requests an unauthorized action or reuses an identifier. | Authentication could be mistaken for Krosna authority. |
| Provider/model | Returns arbitrary text, actions, fake authority, fake receipts, secret-reveal requests, or duplicate calls. | Model-controlled effect, egress, or secret access. |
| Local network peer | Connects to a transport or effect listener, delays, resets, sends malformed frames, or responds with oversized data. | Unauthorized runtime entry, ambiguous network effect, or resource exhaustion. |
| Concurrent filesystem actor | Swaps parents/targets, creates symlinks, reparse points, junctions, hard links, or changes a path after validation. | Path escape, wrong-file read/write, or uncertain effect outcome. |
| Process supervisor/deployer | Misconfigures endpoint, secrets, limits, or process ownership. | A documented runtime guarantee can be disabled by deployment. |
| Host/OS compromise | Reads process memory, handles, files, credentials, logs, or kernel state. | Full compromise outside this runtime model. |

## Boundary review

### Client -> Transport

The transport reads a bounded frame before JSON materialization, rejects
duplicate/unknown security fields, validates request and lifecycle identity,
and authenticates the request before Gateway or Provider invocation. A missing,
invalid, oversized, malformed, stale, or replayed authentication proof is a
terminal denial with zero effects. The client cannot submit policy, Krosna
rules, a `Propusk`, executor configuration, raw endpoint/path/payload, or a
Klyuchnik value.

### Transport -> Gateway

Transport identity is carried as a trusted runtime principal only after the
authenticator accepts the proof. It is not the model principal used in an
action proposal. The Gateway still reconstructs model actions from the fixed
tool catalog and asks Krosna to authorize them. Transport never receives a
provider callback, executor reference, raw secret, or release authority.

### Gateway -> Provider/Model

Provider input is bounded DATA with fixed tool vocabulary. Provider output is
staged text and raw `ActionRequest` proposals only. Provider code cannot
construct `Decision`, `Propusk`, `TrustedControl`, `DeclassificationPermit`,
`ProtectedExecutor`, `SecretBroker`, or a transport-authentication result.
Unknown response forms, malformed calls, duplicate calls, and lifecycle
failure are terminal. No automatic retry follows an uncertain effect.

### Gateway -> Krosna/Ruslo/Zaslon

The Gateway owns ordering, but the core primitives own their distinct
semantics. Krosna is the only authority issuer. Ruslo independently evaluates
direction and provenance. Zaslon owns formal hard-deny content/action gates.
The runtime must not accept a provider/client claim of classification,
destination, allow, declassification, or successful receipt.

### Krosna/Ruslo/Zaslon -> Propusk

An allowed proposal becomes a fresh exact-scope `Propusk` bound to the model
principal, operation, capability, resource, and destination. It is not
serialized over transport, put into a receipt, or retained for a later
lifecycle. Preflight of a complete action batch occurs before the first
effect. A stale, reused, mismatched, or cross-lifecycle token is rejected.

### Propusk -> Executor/Klyuchnik

Only a Tkach-owned executor accepts `Propusk`. The executor owns the OS handle,
socket, fixed binding, and effect classification. Klyuchnik owns raw secret
bytes and exposes only exact broker-side use with a matching token. The model,
client, provider, transport, receipt, and log surfaces receive no raw secret.

### Executor -> Filesystem/Network

The effect side is the narrowest trusted boundary. Filesystem operations use
fixed reviewed resources, bounded data, create-only write semantics, and
platform-specific no-follow adapters where available. Network operations use
fixed loopback identity, bounded request/response data, connect/read/write
timeouts, and Ruslo before connect. A post-attempt failure is
`OUTCOME_UNKNOWN`; it is never silently converted to success or retried.

### Runtime -> Receipt/Client release

Receipts contain operation, resource category, destination category, execution
identity, outcome, and uncertainty only. They are evidence, not authority and
not a `Propusk`. Protected output is released only after final Gateway
Ruslo/Zaslon checks. Errors and observability carry bounded identifiers and
categories, never prompts, protected bytes, network payloads, credentials, or
raw secret values.

## Threat inventory and required controls

| Threat | Required control | Coverage status |
| --- | --- | --- |
| Hostile model proposes arbitrary effect | Fixed provider API, Krosna, Propusk-only executor | Existing; runtime integration must preserve |
| Malformed/oversized transport | Pre-parse frame bound, strict schema, bounded errors | R9/R35 implementation |
| Unauthenticated caller | Authenticator before Gateway/provider/effect | R9/R10 implementation |
| Authentication mistaken for authority | Separate transport principal and model principal | R10 implementation |
| Duplicate/replay/concurrent request | Request/lifecycle identity and bounded replay state | R11 implementation; durable replay out of scope |
| Replay after timeout or unknown outcome | Terminal unknown state, no auto retry, fresh explicit lifecycle | R5/R6/R12/R13 implementation |
| Cancellation during any stage | Cancellation checkpoints and terminal state | R13 implementation |
| Shutdown race | Stop acceptance, barrier, bounded drain, no post-barrier effect | R14 implementation |
| Symlink/reparse/junction/path swap | `symlink_metadata`, OS-aware adapter or explicit denial | Existing partial; R2/R3 hardening |
| Hard-link alias or wrong file identity | Handle/file identity validation where OS supports it; no portable claim | R2/R3 evidence boundary |
| DNS rebinding/redirect/proxy | Fixed loopback `SocketAddr`; no DNS/redirect; future hostname separate model | Existing fixed effect; R7/R8 |
| Oversized compressed/body/error data | Bound encoded frame and decompressed/materialized values | R9/R16 implementation |
| Direct executor/broker bypass | Ownership API and process/isolation contract; no host-wide magical claim | R1/R18/R19 implementation/docs |
| Process-local secret exposure | Private Klyuchnik, redacted surfaces, deployment isolation | Existing partial; R17 hardening |
| Logs/core dumps expose payloads | Safe categories/IDs only and operational policy | R21 implementation/docs |
| Stale `Propusk` | Non-serializable, one-run ownership, no reuse | Existing partial; R11/R13 hardening |
| Partial effect or ambiguous result | Explicit `FAILED_BEFORE_EFFECT` vs `OUTCOME_UNKNOWN` | Existing; R5/R6 integration |
| Hostile resource saturation | Per-request, active, pending, provider, effect, receipt, and error bounds | R15/R16/R29 implementation |
| Fully compromised host/OS | Explicitly outside model | Not claimed |

## Protected, partial, and out of model

### PROTECTED by this phase when correctly deployed

- No effect occurs before transport authentication and Gateway authorization.
- Model/provider data cannot mint authority, widen a capability, or call an
  executor/broker directly through the reviewed runtime API.
- Fixed filesystem and loopback network effects remain bounded and routed
  through `Propusk`, with denial before connect for unauthorized network work.
- Authentication and authorization are separate, replay and duplicate state is
  explicit, and uncertain outcomes are never auto-retried.
- Cancellation, shutdown, concurrency, resource limits, receipts, and safe
  observability have explicit terminal semantics.

### PARTIAL / deployment-dependent

- Portable standard Rust cannot guarantee a handle-relative, no-follow,
  race-free filesystem transaction on every OS. The runtime must choose a
  reviewed platform adapter or deny the profile.
- In-process ownership prevents accidental API bypasses but cannot stop code
  already running with the same process privileges. CONTROLLED/SEALED profiles
  document the process boundary and its residual trust.
- In-memory replay protection is bounded to one runtime instance and does not
  prove durable exactly-once behavior across restart or multiple instances.
- TLS, OS ACLs, job objects/containers, core-dump policy, scheduler isolation,
  and secret-provider deployment are operational controls outside this crate.

### OUT OF MODEL

- Fully compromised host, kernel, OS account, runtime, compiler, or filesystem.
- Semantic prompt-injection detection, model intent correctness, and business
  authorization beyond typed Krosna rules.
- Distributed consensus, durable exactly-once effects, rollback of arbitrary
  external systems, and arbitrary shell/filesystem/network APIs.
- Provider-side built-ins, MCP, Anthropic, new model providers, SDK, UI, cloud
  control plane, browser/computer-use, or internet SaaS integration.

## Security review obligations

Every runtime implementation change must be challenged with a malicious client,
malicious provider, concurrent caller, local receiver, path mutation, fault
injection, shutdown, cancellation, replay, and oversized-input test. A real
defect is recorded with a regression test, fixed at the owning boundary, and
retested before the change is considered evidence. An external scan that does
not reach a terminal artifact is `INCONCLUSIVE / external tooling unavailable`
and is not a security result.
