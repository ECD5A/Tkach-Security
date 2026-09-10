# Tkach Gateway Phase 1 Threat Model

Status: G0-G10 implementation baseline plus the v0.1 OpenAI adapter boundary.
The gateway remains an in-process, synchronous enforcement boundary. The
OpenAI adapter is an additional untrusted provider hop; it does not change
Gateway authority ownership.

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
  -> Ruslo and Zaslon egress checks
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
| Ruslo | `crates/tkach-core/src/ruslo.rs:65-190` models directional flow requests and decisions. |
| Zaslon | `crates/tkach-core/src/zaslon.rs:224-300` and `:331-435` provide action and bounded streaming content gates. |
| Klyuchnik | `crates/tkach-core/src/klyuchnik.rs:134-251` keeps fake broker values private and reveal-denied. |
| Sled/testbed | `crates/tkach-core/src/sled.rs:456-516` records safe decisions and models protected execution. |
| Gateway | `crates/tkach-gateway`: bounded protocol boundary, lifecycle, provider invocation, staging, ordering, and Propusk-only tool dispatch. |
| OpenAI adapter | `crates/tkach-provider-openai`: trusted credential/endpoint boundary, bounded HTTPS transport, strict Responses parser, fixed proposal mapping, replay markers, and stateless tool-result pairing. |

### Implemented resource budgets

These gateway-owned budgets are enforced before provider release or, where
applicable, before a protected effect:

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
| Protected tool result | 16 KiB |
| Model context | 256 KiB / 64 items |
| Action requests per provider turn | 32 |
| Provider/tool turns | 8 |

The budgets are defensive availability controls, not policy authority. An
over-limit or malformed input fails closed and cannot invoke a provider,
executor, broker, or egress sink.

## Real OpenAI adapter boundary

The adapter is tested with a fake transport and with the actual Gateway
orchestrator. A completed `harmless_read` response becomes a raw proposal,
passes Krosna and Ruslo, reaches the fake executor only as a Propusk, and
returns a bounded tool result for the next stateless Responses turn. An
`external_send` response is denied by Gateway policy and reaches no executor
effect. Unknown provider item types, malicious arguments, duplicate/replayed
IDs, transport timeouts, and oversized tool results fail before release or
effect.

The adapter sends `store:false`, does not use provider conversations,
`previous_response_id`, background mode, built-in tools, MCP, or automatic
retry. Its HTTPS transport rejects redirects and bounds both successful and
error response reads. Streaming is intentionally not implemented in this
milestone; the synchronous Gateway continues to require complete buffered
output before final egress checks.

## Threat Model, Trust Boundaries, and Assumptions

### Protected assets

- kernel-issued `Propusk` values and the exact scope they bind;
- protected tool effects, writes, network sends, and broker operations;
- raw fake/real secret values held behind Klyuchnik;
- protected model context, Niti lineage, and Metka classification;
- policy and hard-deny semantics in Krosna, Ruslo, and Zaslon;
- safe Sled evidence without protected payloads;
- availability of the gateway's bounded request lifecycle.

### Actors and capabilities

| Actor | Starting capabilities | Not granted at the boundary |
| --- | --- | --- |
| Client/external caller | Sends bounded request bytes and untrusted content. | Policy mutation, Propusk, trusted context, direct tool or broker access. |
| Hostile provider/model | Sees the model request and may return arbitrary bounded chunks/actions, including forged-looking fields. | Decision construction, Propusk construction, trusted Niti/Metka mutation, raw secret access, executor reference. |
| Gateway orchestrator | Owns lifecycle and calls core APIs in fixed order. | Must not reinterpret core decisions or duplicate policy semantics. |
| Fake tool broker | Receives only kernel-issued Propusk. | Raw ActionRequest, provider identity, direct provider callback. |
| Klyuchnik broker | Owns fake raw secret values and may use them for an authorized operation. | Raw secret return to provider/model/client. |
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
   final Niti/Metka, Ruslo, and Zaslon evaluation. A timeout, malformed response,
   cancellation, or failed check discards staged output.
7. **Gateway -> Klyuchnik.** Only a valid, exact secret-use Propusk reaches the
   fake broker. Handles are opaque labels; raw values never enter provider
   output, Sled, errors, or release buffers.
8. **Gateway -> Sled.** Sled is evidence, not authority. Gateway never trusts a
   received or deserialized receipt/trace as permission.

### Threat scenarios

The following were G0 hypotheses. G1-G10 tests now provide the evidence listed
in the control column; residual assumptions remain explicit below.

| Priority | Scenario and capability gain | Prerequisites | Expected control | Evidence/uncertainty |
| --- | --- | --- | --- | --- |
| Critical | Provider calls protected executor directly, gaining an effect without policy. | Provider obtains an executor reference or gateway exposes raw dispatch. | Provider trait exposes proposals only; gateway-owned executor accepts Propusk only. | Covered by trait/API shape and hostile-provider tests. |
| Critical | Provider obtains raw broker secret and returns it to the client. | Secret is copied into provider request or broker return value. | Klyuchnik uses opaque handles and internal operation; staged output and debug/error surfaces are redacted. | Covered by Klyuchnik and Gateway secret-use/reveal tests. |
| High | Protected model output is released before final authorization. | Streaming sink writes directly to client or network. | Buffer all security-relevant chunks; run Ruslo/Zaslon before one final release. | Covered by cross-chunk and rejected-final-output tests. |
| High | Malformed/timeout provider response leaves a partial protected effect. | Gateway executes actions while response is incomplete. | Stage response and actions; failure/timeout/cancellation discards staging. | Covered by hostile lifecycle tests. |
| High | Untrusted content is mapped to trusted system control. | Adapter accepts caller-provided role/trust/authority fields. | External schema has data-only roles; Gnezdo creates DATA; no public control constructor. | Covered by ingress and core data-lane tests. |
| High | Size-limit bypass causes memory/CPU exhaustion. | Limit checked after deserialization or per-message but not cumulative. | Raw body bound first; bounded vectors/strings/chunks/results/context and cumulative output budget. | Covered by raw, chunk, core, and fuzz parser checks. |
| High | Provider strips Niti/Metka or claims a public/declassified output. | Provider response carries authority metadata trusted by gateway. | Provider response contains no security metadata; gateway derives output from staged protected inputs and re-evaluates flow. | Covered by metadata-stripping and hostile export tests. |
| High | Egress destination is confused with model context or internal response. | One generic destination path is reused for public sends and client release. | Typed destination mapping; explicit public external action path; final release destination is policy-configured. | Covered by public export and invalid-sink tests. |
| Medium | Duplicate/unknown fields create parser ambiguity or smuggle control. | Permissive deserializer or inconsistent adapters. | Strict schema, duplicate rejection, bounded reader, no unknown security fields. | Covered by duplicate-field/name and fuzz parser tests. |
| Medium | Cancellation/reuse/replay applies stale authorization. | Propusk or staged state survives a failed turn and is reused. | Per-turn state ownership, no token serialization, terminal failed lifecycle, fresh authorization per action, replay rejection. | Covered by failure/cancellation/replay tests. |
| Medium | Sled/receipt metadata leaks protected labels or is treated as permission. | Trace contains payloads or gateway trusts a receipt. | Use core safe evidence and output-only artifacts; do not accept trace/receipt as input authority. | Covered by redacted trace/receipt tests and API shape. |

### Assumptions and unresolved questions

- The host process and operating system are not fully compromised; this is the
  same Klyuchnik limit documented by Strong Core.
- The provider may be completely controlled by an attacker. No provider
  behavior is used as an authority signal.
- Any future transport must preserve the same bounded-reader and
  no-premature-release contract. The current OpenAI adapter implements only
  the bounded provider HTTPS call; it is not a production gateway transport.
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
Ruslo/Zaslon. Secret use passes Klyuchnik and returns only a payload-free result.
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

## Gateway Hardening 1.5 update

The hardening pass formalized the lifecycle and effect contract before any
provider adapter:

- provider output remains staged until final flow and egress-Zaslon approval;
- every action proposal is preflighted before executor calls;
- at most one non-read action is allowed per turn, while awaited turns are
  read-only and later failures cannot create an irreversible effect;
- `ExternalRequest::new` enforces aggregate message, metadata, tool-label, and
  semantic request budgets in addition to per-field and raw-wire limits;
- the Gateway owns a private fail-closed lifecycle state machine and never
  exposes reusable Propusk values;
- timeout, cancellation, malformed output, duplicate/replayed action, and
  terminal egress denial discard staged output and pending actions;
- the complete 319-mutant Gateway run left 31 survivors, all classified as
  diagnostic-only, public-API-unreachable, or equivalent defense-in-depth
  behavior. No unexplained security-relevant survivor remains.

Phase 1 remains a synchronous in-process boundary. It does not claim
transactional rollback for arbitrary external systems; instead it prevents
premature irreversible execution and intentionally rejects multi-write batches.

Repository: Tkach-Security
Version: strong-core-v0.1 / 585bde22f7b39ee227c1b6e7876cb7999643ca6f
Gateway implementation: `1e1d16c`, hardening: `36ce4f7`, packaging:
`9026605`; Gateway Hardening 1.5 is tagged locally as `gateway-v0.1`.
