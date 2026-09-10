# Tkach Gateway Phase 1 Threat Model

Status: G0 design baseline. The gateway described here is an in-process,
synchronous, provider-independent boundary. It is not yet implemented at the
time of this document's initial commit. Every control marked planned must be
proven by Gateway Phase 1 tests before it is treated as a guarantee.

## Overview

Gateway Phase 1 turns the provider-independent Strong Core into an execution
boundary around hostile test doubles. The intended flow is:

```text
External request
  -> bounded read and strict validation
  -> Zaslon ingress
  -> Gnezdo DATA containment
  -> internal SecurityEnvelope
  -> untrusted provider/model boundary
  -> bounded provider response staging
  -> Niti/Metka derivation
  -> Krosna authorization
  -> Propusk-only tool execution
  -> Diode and Zaslon egress checks
  -> release or deny
```

The central invariant is:

> NO PROTECTED EFFECT OR PROTECTED EGRESS MAY BYPASS TKACH ENFORCEMENT.

The provider abstraction returns only untrusted text chunks and proposed
`ActionRequest` values. It cannot return `Decision`, `Propusk`, trusted
provenance, declassification authority, or raw broker material. Gateway code
is an orchestrator, not a second policy engine: authorization and flow
semantics remain in `tkach-core`.

| Boundary/component | Source-backed baseline or planned responsibility |
| --- | --- |
| Strong Core | `crates/tkach-core/src/lib.rs:22-46` exposes the provider-independent primitives. |
| Security domain | `crates/tkach-core/src/domain.rs:732-900` separates request data from validated context and authority. |
| Gnezdo | `crates/tkach-core/src/gnezdo.rs:46-155` contains untrusted content in DATA with no public promotion path. |
| Krosna | `crates/tkach-core/src/krosna.rs:373-475` evaluates gates and is the only production path that mints Propusk. |
| Propusk/executor | `crates/tkach-core/src/propusk.rs:80-127` prevents raw ActionRequest execution. |
| Diode | `crates/tkach-core/src/diode.rs:65-190` models directional flow requests and decisions. |
| Zaslon | `crates/tkach-core/src/zaslon.rs:224-300` and `:331-435` provide action and bounded streaming content gates. |
| Pechat | `crates/tkach-core/src/pechat.rs:134-251` keeps fake broker values private and reveal-denied. |
| Sled/testbed | `crates/tkach-core/src/sled.rs:456-516` records safe decisions and models protected execution. |
| Gateway | Planned `tkach-gateway`: bounded protocol boundary, lifecycle, provider invocation, staging, ordering, and tool dispatch. |

### Planned resource budgets

These are gateway-owned budgets and must be enforced before any protected
effect or provider release. Exact constants will be committed with G1/G2 and
tested at boundary and over-limit values.

| Resource | Initial budget |
| --- | ---: |
| Raw request body | 64 KiB |
| Messages | 32 |
| Message bytes | 16 KiB each |
| Metadata entries | 32 |
| Metadata key/value | 128 / 1 KiB |
| Tool declarations | 16 |
| Provider output bytes | 64 KiB |
| Provider stream chunks | 64 |
| Cumulative staged output | 256 KiB |
| Action requests per provider turn | 32 |

The budgets are defensive availability controls, not policy authority. An
over-limit or malformed input fails closed and cannot invoke a provider,
executor, broker, or egress sink.

## Threat Model, Trust Boundaries, and Assumptions

### Protected assets

- kernel-issued `Propusk` values and the exact scope they bind;
- protected tool effects, writes, network sends, and broker operations;
- raw fake/real secret values held behind Pechat;
- protected model context, Niti lineage, and Metka classification;
- policy and hard-deny semantics in Krosna, Diode, and Zaslon;
- safe Sled evidence without protected payloads;
- availability of the gateway's bounded request lifecycle.

### Actors and capabilities

| Actor | Starting capabilities | Not granted at the boundary |
| --- | --- | --- |
| Client/external caller | Sends bounded request bytes and untrusted content. | Policy mutation, Propusk, trusted context, direct tool or broker access. |
| Hostile provider/model | Sees the model request and may return arbitrary bounded chunks/actions, including forged-looking fields. | Decision construction, Propusk construction, trusted Niti/Metka mutation, raw secret access, executor reference. |
| Gateway orchestrator | Owns lifecycle and calls core APIs in fixed order. | Must not reinterpret core decisions or duplicate policy semantics. |
| Fake tool broker | Receives only kernel-issued Propusk. | Raw ActionRequest, provider identity, direct provider callback. |
| Pechat broker | Owns fake raw secret values and may use them for an authorized operation. | Raw secret return to provider/model/client. |
| Strong Core | Trusted TCB for typed authorization and flow decisions. | Provider-specific protocol interpretation. |

### Trust boundaries and expected controls

1. **Client -> Gateway.** Raw bytes are bounded before generic JSON
   materialization. Strict schemas, count/byte budgets, and fail-closed parse
   errors prevent parser ambiguity and resource exhaustion.
2. **Gateway -> Zaslon/Gnezdo.** External instructions become DATA, never
   trusted CONTROL. Ingress hard-deny is applied before provider invocation.
3. **Gateway -> Provider.** Provider output is model-originated and untrusted.
   The adapter cannot manufacture authority-bearing core values; all output is
   staged and bounded.
4. **Provider -> Gateway actions.** An action is only a proposal. Gateway
   maps it to a core `ActionRequest`, calls Krosna, and passes only the
   resulting Propusk to a tool executor.
5. **Gateway -> Tool.** No provider-held callback or executor reference exists.
   Protected tools are gateway-owned and receive only `Propusk`.
6. **Gateway -> Network/client egress.** No staged bytes are released before
   final Niti/Metka, Diode, and Zaslon evaluation. A timeout, malformed response,
   cancellation, or failed check discards staged output.
7. **Gateway -> Pechat.** Only a valid, exact secret-use Propusk reaches the
   fake broker. Handles are opaque labels; raw values never enter provider
   output, Sled, errors, or release buffers.
8. **Gateway -> Sled.** Sled is evidence, not authority. Gateway never trusts a
   received or deserialized receipt/trace as permission.

### Threat scenarios

The following are hypotheses for the planned gateway boundary, not findings in
the unimplemented crate.

| Priority | Scenario and capability gain | Prerequisites | Expected control | Evidence/uncertainty |
| --- | --- | --- | --- | --- |
| Critical | Provider calls protected executor directly, gaining an effect without policy. | Provider obtains an executor reference or gateway exposes raw dispatch. | Provider trait exposes proposals only; gateway-owned executor accepts Propusk only. | Core type boundary is implemented; gateway path is pending. |
| Critical | Provider obtains raw broker secret and returns it to the client. | Secret is copied into provider request or broker return value. | Pechat uses opaque handles and internal operation; staged output and debug/error surfaces are redacted. | Core broker control is source-backed; provider integration is pending. |
| High | Protected model output is released before final authorization. | Streaming sink writes directly to client or network. | Buffer all security-relevant chunks; run Diode/Zaslon before one final release. | Requires implementation and partial-output tests. |
| High | Malformed/timeout provider response leaves a partial protected effect. | Gateway executes actions while response is incomplete. | Stage response and actions; execute only after complete successful provider turn, or explicitly fail closed. | Lifecycle design is planned. |
| High | Untrusted content is mapped to trusted system control. | Adapter accepts caller-provided role/trust/authority fields. | External schema has data-only roles; Gnezdo creates DATA; no public control constructor. | Core Gnezdo control is source-backed; schema is pending. |
| High | Size-limit bypass causes memory/CPU exhaustion. | Limit checked after deserialization or per-message but not cumulative. | Raw body bound first; bounded vectors/strings/chunks and cumulative output budget. | Core has independent bounds; gateway budgets are pending. |
| High | Provider strips Niti/Metka or claims a public/declassified output. | Provider response carries authority metadata trusted by gateway. | Provider response contains no security metadata; gateway derives output from staged protected inputs and re-evaluates flow. | Requires integration regression tests. |
| High | Egress destination is confused with model context or internal response. | One generic destination path is reused for public sends and client release. | Typed destination mapping; explicit public external action path; final release destination is policy-configured. | Destination semantics exist in core; gateway mapping is pending. |
| Medium | Duplicate/unknown fields create parser ambiguity or smuggle control. | Permissive deserializer or inconsistent adapters. | Strict schema, duplicate rejection, bounded reader, no unknown security fields. | Needs malformed JSON tests. |
| Medium | Cancellation/reuse/replay applies stale authorization. | Propusk or staged state survives a failed turn and is reused. | Per-turn state ownership, no token serialization, terminal failed lifecycle, fresh authorization per action. | Core Propusk is non-deserializable; lifecycle pending. |
| Medium | Sled/receipt metadata leaks protected labels or is treated as permission. | Trace contains payloads or gateway trusts a receipt. | Use core safe evidence and output-only artifacts; do not accept trace/receipt as input authority. | Core control is source-backed; gateway tests pending. |

### Assumptions and unresolved questions

- The host process and operating system are not fully compromised; this is the
  same Pechat limit documented by Strong Core.
- The provider may be completely controlled by an attacker. No provider
  behavior is used as an authority signal.
- A future real transport must preserve the same bounded-reader and
  no-premature-release contract; Phase 1 does not implement HTTP, streaming
  sockets, authentication, or provider SDKs.
- The gateway's trusted configuration supplies the Krosna and tool catalog. A
  client request cannot replace policy or add a privileged tool.
- Independent architecture delegation was unavailable in this environment;
  the parent agent performed the source-backed review sequentially. This is a
  process limitation, not evidence that a control works.
- Whether a later deployment permits a client-facing response to contain
  protected-derived data is a deployment policy question. Phase 1 defaults to
  conservative final egress denial for protected-derived public output.

## Attack Surface, Mitigations, and Attacker Stories

### Client -> Gateway

The attacker controls request bytes, message content, metadata values, and
declared tool names. They do not control the gateway's policy, tool catalog,
provider implementation selected by trusted configuration, or core-issued
authority. The gateway must bound and validate before invoking any provider or
protected component.

### Gateway -> Model/provider

The provider is intentionally hostile. It may emit prompt-injected text,
authority claims, forged structured actions, malformed chunks, handle-reveal
requests, protected exports, or arbitrary ordering. The adapter must map all
of these to untrusted data/proposals and never preserve provider-supplied
security metadata.

### Gateway -> Tool/network/secret broker

All effects are capability-mediated. A raw action is denied by Krosna or never
reaches the executor. Public network sends are separate from reads and pass
Diode/Zaslon. Secret use passes Pechat and returns only a payload-free result.
The gateway must not expose executor or broker references through the provider
trait, callbacks, request objects, logs, or errors.

### Severity calibration

- **Critical:** an attacker-controlled provider can execute a protected tool,
  send protected data externally, or retrieve raw broker material without a
  valid Tkach authorization boundary.
- **High:** an attacker can cause protected bytes to be released before final
  flow/content authorization, or can bypass lifecycle/size controls to create a
  material integrity or availability failure across the boundary.
- **Medium:** a bounded metadata leak, stale-state/replay condition, parser
  ambiguity, or denial of service remains but does not create a new protected
  effect under the tested policy.
- **Low:** diagnostic or compatibility behavior that is explicitly documented,
  bounded, and does not grant protected authority or raw secret access.

Provider prompt injection, semantic intent confusion, and an already fully
compromised host are not by themselves gateway findings. They become findings
only when they produce a new path around Tkach authorization or information
flow controls.

## G0 exit criteria

G0 is complete when this document is committed and the implementation plan
preserves the following invariant:

> NO PROTECTED EFFECT OR PROTECTED EGRESS MAY BYPASS TKACH ENFORCEMENT.

G1-G10 must provide source-backed tests for every planned control before the
Gateway Phase 1 checkpoint can pass.

Repository: Tkach-Security
Version: strong-core-v0.1 / 585bde22f7b39ee227c1b6e7876cb7999643ca6f
