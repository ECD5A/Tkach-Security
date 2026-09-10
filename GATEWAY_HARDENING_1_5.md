# Gateway Hardening 1.5

Status: implemented on the provider-independent Gateway Phase 1 boundary.

This document freezes the Phase 1 execution semantics before any real
provider adapter. It does not authorize OpenAI, Anthropic, MCP, SDK, HTTP,
cloud, UI, or production transport work.

## Effect-ordering invariant

**No irreversible protected effect may occur before every security gate
required for that effect has succeeded.**

Gateway Phase 1 uses staged-effects semantics. Provider chunks and proposals
are staged first. Every proposal in a batch is validated and authorized before
the first proposal is handed to the `ProtectedExecutor`. A complete turn runs
final output size, provenance/flow, and egress-Zaslon checks before execution.
There is no rollback claim.

The Phase 1 contract therefore limits each turn to at most one non-read action.
Read-only tool calls may be committed before a later provider turn because a
read is not an irreversible write, network send, or secret release. If a later
turn fails, those reads remain evidence in the fake broker log, but no
irreversible effect or staged output is released. Multiple writes, or a write
mixed with another non-read action, are rejected before execution.

## Lifecycle state machine

The implementation owns an internal `LifecycleState`; providers and release
adapters cannot construct or mutate it. Any transition outside this table
fails closed with `InvalidLifecycle`.

| State | Entry condition | Allowed next states | Protected effect permitted? |
|---|---|---|---|
| `Received` | Gateway method entered | `Validated` | No |
| `Validated` | Release destination and request boundary accepted | `Contained` | No |
| `Contained` | Gnezdo and ingress Zaslon completed | `ProviderRunning` | No |
| `ProviderRunning` | Provider invocation is active | `OutputStaged` or terminal error | No |
| `OutputStaged` | Sink accepted the bounded turn | `EgressApproved` or `ActionsEvaluated` | No |
| `EgressApproved` | Complete output passed all final egress gates | `ActionsEvaluated` | No |
| `ActionsEvaluated` | Every action in the batch passed Krosna | `EffectsCommitted` | No |
| `EffectsCommitted` | Propusk-only executor completed staged actions | `ProviderRunning` or `Released` | Only the already-gated action |
| `Released` | Final result is returned | None | No new effect |

`ProviderStep::AwaitToolResults` cannot carry a non-read action. A complete
step cannot be replayed, a duplicate action cannot be reused in a later turn,
and a provider failure, timeout, cancellation, malformed step, or turn limit
never transitions to `Released`.

## Multi-action semantics

Phase 1 is intentionally not a general transaction manager:

- action proposals are an atomic authorization batch: all must pass Krosna
  before any executor call;
- read-only results are sequentially committed as model context for the next
  bounded turn;
- irreversible effects are staged and sequentially committed only after final
  egress approval, with one non-read action maximum per turn;
- executor rollback is not assumed. The architecture prevents a later
  security denial from following an already-committed irreversible effect.

Consequently, first-read/second-denied-write, secret-use/forbidden-send,
multiple-write, duplicate-id, reordered-replay, and later-turn replay cases
fail before the first irreversible effect. A read followed by a denied action
also remains entirely preflighted: the read is not executed.

## Provider trait review

The `Provider` implementation receives only an immutable `ProviderRequest` and
a `ProviderSink`. The sink can stage bounded text and typed `ActionRequest`
proposals; it cannot issue `Propusk`, call a broker, construct trusted Niti or
Metka, change policy, release output, access Klyuchnik, or retain an executor
reference supplied by the Gateway. `ProviderRequest` contains only bounded
model inputs, metadata, and a fixed tool vocabulary. Provider output has no
security metadata and is conservatively re-derived by the Gateway.

## Boundary and wire review

Gateway-visible authority objects are intentionally non-deserializable where
authority would be implied. `GatewayResult`, `GatewayError`, `ProviderRequest`,
`ModelInput`, `ToolDescription`, and `EffectReceipt` have no public authority
constructor. `Clone`, accessors, `Debug`, and receipts expose data/evidence
only; diagnostics are payload-safe and never consulted for an allow decision.

External JSON uses private strict wire types with duplicate-key rejection,
unknown-field rejection, bounded strings/sequences, duplicate metadata-name
rejection, explicit null-vs-omitted behavior, token validation, and bounded
aggregate message/metadata/tool/request envelopes. Provider staging has both
per-chunk and cumulative limits; model context and tool results have separate
aggregate limits.

## Cancellation and timeout

Provider errors discard the current sink, including staged text and action
proposals. A timeout or cancellation after a proposal therefore cannot execute
that proposal. If a read was already committed to obtain a subsequent turn,
the next-turn error may leave that non-irreversible read in evidence, but it
cannot release output, execute a pending write/send/secret effect, or reuse a
Propusk. Propusk values never cross the provider boundary and are not stored
for replay.

## Missed-mutant triage policy

The final mutation run is recorded in `DEVELOPMENT.md`. Every survivor is
classified there by exact location and mutation. Diagnostics/accessors are
`DIAGNOSTIC_ONLY` because changing them cannot feed a policy decision. The
metadata aggregate arithmetic survivor is `EQUIVALENT`: its component count and
per-entry limits already make the alternate larger bound unreachable. Coupled
fake-read and network guard survivors are `UNREACHABLE_BY_PUBLIC_API` where
Krosna cannot mint the malformed Propusk needed to reach that branch; focused
tests prove the public type boundary. No `SECURITY_RELEVANT` survivor is left
unexplained.

## Independent oracle

`tests/gateway_boundary.rs` contains a small, deliberately separate lifecycle
oracle. It does not call Gateway transition code. It checks the cross-product
rule that terminal denial/error, unapproved egress, cancellation, and
non-evaluated output cannot authorize an irreversible write, external send,
or secret use; read remains non-irreversible by the Phase 1 contract.

## Complete missed-mutant ledger

The final run had 31 survivors (319 tested, 221 caught, 67 unviable). The
location and mutation below are the
complete list; categories are intentionally explicit.

| Location | Mutation | Category | Rationale |
|---|---|---|---|
| `input.rs:47` | `ExternalRole::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Debug text only; role is never an authority input. |
| `input.rs:65` | `ExternalMessage::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Redacted diagnostic only. |
| `input.rs:111` | `MetadataEntry::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Metadata debug output cannot affect policy. |
| `input.rs:143` | `ToolDeclaration::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Client label diagnostics are not the trusted catalog. |
| `input.rs:180` | `ExternalRequest::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Count-only diagnostics are non-authoritative. |
| `input.rs:327` | bounded-string `expecting -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Parser error wording only; acceptance path is unchanged. |
| `input.rs:368` | bounded-vector `expecting -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Parser error wording only. |
| `provider.rs:35` | `ModelInput::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Provider debug representation is not fed back to Gateway. |
| `provider.rs:114` | `ProviderRequest::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Request counts/turn diagnostics only. |
| `provider.rs:348` | `DeterministicProvider::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Test-double diagnostics only. |
| `provider.rs:393` | `ScriptedStep::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Test-double diagnostics only. |
| `provider.rs:426` | `HostileProvider::fmt -> Ok(Default::default())` | `DIAGNOSTIC_ONLY` | Test-double diagnostics only. |
| `tools.rs:35` | `EffectReceipt::fmt -> redacted default` | `DIAGNOSTIC_ONLY` | Receipt debug cannot authorize or release. |
| `tools.rs:71` | `ToolResult::fmt -> redacted default` | `DIAGNOSTIC_ONLY` | Tool debug output is non-authoritative. |
| `tools.rs:92` | `FakeToolBroker::fmt -> redacted default` | `DIAGNOSTIC_ONLY` | Broker diagnostics only. |
| `tools.rs:149` | `external_send_count -> 0` | `DIAGNOSTIC_ONLY` | Counter is test observability; it is not consulted by routing or policy. |
| `tools.rs:155` | `effects -> Vec::leak(Vec::new())` | `DIAGNOSTIC_ONLY` | Receipt accessor exposes evidence only; execution already occurred. |
| `tools.rs:177` | protected-read guard `|| -> &&` | `UNREACHABLE_BY_PUBLIC_API` | A `database.read` capability with the coupled wrong shape cannot receive a public Propusk; Krosna proof test covers it. |
| `tools.rs:178` | protected-read guard `|| -> &&` | `UNREACHABLE_BY_PUBLIC_API` | Resource kind and `database.read` are coupled by Krosna's known-capability table. |
| `tools.rs:202` | harmless-read guard `|| -> &&` | `UNREACHABLE_BY_PUBLIC_API` | Same coupled capability boundary for the harmless route. |
| `tools.rs:203` | harmless-read guard `|| -> &&` | `UNREACHABLE_BY_PUBLIC_API` | Same coupled resource-kind boundary for the harmless route. |
| `tools.rs:245` | executor dispatch `&& -> ||` | `EQUIVALENT` | Any newly selected malformed read route is rejected by the exact helper guard; valid routes are unchanged. |
| `tools.rs:260` | network operation `== -> !=` | `UNREACHABLE_BY_PUBLIC_API` | Operation/network capability pairing is rejected by Krosna before Propusk minting. |
| `tools.rs:261` | network capability `== -> !=` | `UNREACHABLE_BY_PUBLIC_API` | `network.send` is coupled to `NetworkSend` by Krosna. |
| `tools.rs:262` | network kind `== -> !=` | `UNREACHABLE_BY_PUBLIC_API` | Network kind is coupled to `network.send` by Krosna. |
| `tools.rs:265` | network capacity `>= -> <` | `UNREACHABLE_BY_PUBLIC_API` | The public network route is hard-denied for the Gateway's untrusted context; no public Propusk reaches this guard. |
| `tools.rs:268` | `external_send_count += 1 -> -= 1` | `DIAGNOSTIC_ONLY` | Counter has no authority or effect semantics; public route is also unreachable. |
| `tools.rs:268` | `external_send_count += 1 -> *= 1` | `DIAGNOSTIC_ONLY` | Same non-authoritative counter rationale. |
| `tools.rs:274` | secret-use operation guard `&& -> ||` | `UNREACHABLE_BY_PUBLIC_API` | Klyuchnik/Krosna exact-route hard deny prevents malformed secret permits. |
| `tools.rs:275` | secret-use capability guard `&& -> ||` | `UNREACHABLE_BY_PUBLIC_API` | `secret.use` is only known for the exact secret operation route. |
| `tools.rs:276` | secret-use kind guard `&& -> ||` | `UNREACHABLE_BY_PUBLIC_API` | Secret resource kind is enforced before Propusk issuance. |

The focused tests deliberately kill all reachable budget, lifecycle, staging,
authorization, routing-destination, and effect-order mutants. The remaining
diagnostic and public-type-boundary survivors cannot create a protected effect
or alter an allow/deny decision.
