# Architecture

This document describes the current implemented architecture. For the single
short state summary and active phase, see `CURRENT_BASELINE.md` and `ROADMAP.md`.
Historical checkpoint instructions are evidence, not active mandates.

## Implemented baseline

The repository currently contains a provider-independent `tkach-core` crate
and a separate in-process `tkach-gateway` crate. The core has an explicit domain module with validated
security types and a synchronous Krosna evaluator. It has no provider,
network, database, runtime, or external execution dependency.

Zaslon provides sorted, unique action hard-deny rules and formal content rules.
Its canonicalizer uses only ASCII lowercase and ASCII-space folding; controls,
non-ASCII (including zero-width and bidi), backslash escapes, and empty/oversize
values are rejected. Its streaming matcher retains a suffix so a forbidden
sequence cannot be bypassed by chunking. A stream is non-releasable until
explicit `finish()` and becomes terminal after a clear result; post-finish
input is denied. Zaslon reports ingress and egress separately and can be
installed ahead of Krosna policy.

Krosna applies these gates in a fixed order: invalid principal/context,
unknown operation or destination, trusted-control requirements, protected
public-export denial, then policy rules ordered by `HardDeny`, `Deny`,
`RequireApproval`, `Allow`; an unmatched request denies. Within one effect
class, the lexicographically smallest rule ID supplies stable evidence. Policy
rule order therefore does not alter authorization.

The red-team boundary is explicit: the public untrusted-context constructor
normalizes the authority/trust/lane tuple to model/unknown data, rejects trusted
`System` provenance, and Krosna rejects attempts to pair an untrusted context
with a non-model principal. Public Gnezdo containment and tagged-data roots
accept content only and assign conservative unknown metadata. The
context-to-Ruslo mapper is crate-private; public tagged-data flow mapping fixes
the source to the model. These restrictions prevent caller-controlled identity
or provenance metadata from becoming authority.

The resource-boundary pass adds explicit budgets before allocation or indexing:
Zaslon and Ruslo rules are bounded; provenance lineage and derivation parents
are bounded and canonicalized; model fixtures, Sled traces, Klyuchnik entries,
secret values, and Zaslon stream input are bounded. A streaming Zaslon scan
returns `NeedMoreData` until explicitly finished, so an intermediate result is
never a release permission.

## Implemented Strong Core shape

```text
validated SecurityEnvelope
          |
          v
        Krosna
   /      |       \
Zaslon  Propusk  Ruslo
   \      |       /
      decision + Sled
          |
     Klyuchnik boundary
```

Gnezdo contains untrusted content in a data lane. Niti and Metka preserve
provenance and conservative classification. No model output is trusted as
policy or authority. The protected executor boundary accepts only kernel-issued
authorization.

## Trusted Computing Base

The TCB is the typed domain and synchronous policy kernel in `tkach-core`, plus
Rust's type/visibility rules. Policy and
provenance deserialization re-run validation before entering the domain.
Adapters, logging, serialization boundaries, and provider integrations must not
define security semantics. Zaslon does not claim semantic prompt-injection
detection; its guarantee is limited to configured formal representations.

Gnezdo's `UntrustedContent` is a model-readable DATA-lane value whose context is
always `Lane::Data`, `Authority::None`, and `Trust::Untrusted`. Public
containment creates an unknown root; internal trusted ingress mapping is the
only place that can attach richer metadata. Derived values join parent
classifications and preserve parent provenance, with bounded overflow falling
back to unknown-derived state. There is no public DATA-to-CONTROL constructor;
the opaque `TrustedControl` type has a private field and is not deserializable.
Natural-language content is not interpreted as policy, capability,
declassification, or authority. Its debug surface redacts the content, as do
generic `TaggedData<T>`, Zaslon matcher state, and the streaming matcher tail.

Propusk is issued only by `Krosna::authorize` after an explicit allow. The
resulting `AuthorizedAction` contains a private request/grant pair and validates
that principal, operation, capability, and exact resource scope agree. The
public `ProtectedExecutor` trait accepts the `Propusk` alias, never a raw
`ActionRequest`. The initial scope supports exact resources and canonical
relative file prefixes with complete-segment matching.

Niti wraps retained provenance and Metka wraps classification. `TaggedData<T>`
derivation joins every parent thread and takes the most restrictive class, so a
model summary of mixed public/secret input remains protected-derived. Lowering a
Metka requires an opaque `DeclassificationPermit`; there is no public issuer,
and model self-declassification always returns an error.

Ruslo evaluates an explicit directed `FlowRequest` with source endpoint,
destination, flow operation, provenance, and classification. It has fixed effect
precedence and default denial; unknown endpoints/operations and protected
export to `PublicExternal` are denied. Public tagged-data mapping fixes the
source as `Model` and copies Niti/Metka, while Krosna's context mapper is
crate-private. Action mapping treats a resource read/reveal as resource-origin
and every model-controlled write, execute, network, declassification, or policy
effect as model-origin; a model-to-internal deny therefore cannot be bypassed by
a write mislabeled as resource-origin. Thus `READ` into model context is not an
inferred `EXPORT`, and reverse/onward edges require their own rules.

Klyuchnik exposes only validated `SecretHandle` values to model-facing code. The
fake broker stores raw bytes in a private non-serializable `SecretValue`, bounds
entry, per-value, and aggregate-byte capacity, accepts only a Krosna-issued exact `Propusk` for
`secret.use`, and refuses every reveal request. Receipts, errors, and debug
output contain no broker secret.

Sled records bounded, trace-local decision IDs alongside the existing typed
evidence and serializes only those payload-free records. Decision construction
and trace recording are crate-internal; execution and broker receipts are
read-only output artifacts, not deserializable authority inputs. Request-bearing
principal, capability, provenance, operation, and destination values are
projected to payload-free evidence categories, while validated policy rule IDs
remain separate trusted configuration labels for explainability. The enforcement
testbed models hostile proposals, sends allowed non-secret effects through a
`ProtectedExecutor`, and routes an authorized secret-use effect through Klyuchnik;
missing broker or token conversion fails closed. The fake executor also rejects
any direct `SecretBroker` destination, even if a malformed or non-secret
authorized action reaches that defense-in-depth boundary.

Zaslon streaming matching uses incremental prefix state rather than cloning a
rule-sized suffix for every chunk. It also enforces aggregate pattern memory,
rule count, and cumulative input budgets.

Independent composition tests exercise Gnezdo, Zaslon, Propusk, Ruslo,
Niti/Metka, Klyuchnik, and Sled together. They include detection-independent and
multiple-defense-failure scenarios; no heuristic result is treated as an
authority input. In-crate and integration oracle suites independently enumerate
authority/lane, capability/scope, classification/destination, flow direction,
secret-handle, unknown-state, and public-API combinations. Serialization of
model-readable data is not itself an egress permit; release adapters remain
responsible for applying the directional and content gates.

## Gateway Phase 1 boundary

`tkach-gateway` owns only bounded ingress, lifecycle, provider orchestration,
response staging, and dispatch. `ExternalRequest` rejects unknown fields,
duplicate metadata names, oversized raw bodies, strings, collections, and
ambiguous roles before provider invocation. Each message enters Gnezdo and
ingress Zaslon before a private SecurityEnvelope is built.

The provider trait can emit bounded text chunks and typed `ActionRequest`
proposals only. It has no executor, broker, Propusk, Decision, release, or
trusted-metadata API. Provider output is staged; a complete final response is
derived from all protected tool inputs, checked by Krosna/Ruslo and egress
Zaslon, and only then returned. A response with actions cannot leave an
authorized effect behind if its final output gate fails. Awaited turns accept
read-only actions only, and replayed action requests are rejected within a
request lifecycle.

Tool execution is a gateway-owned `ProtectedExecutor` boundary receiving only
core-issued Propusk values. The deterministic fake broker supports protected reads,
harmless reads, a bounded write, external-send attempts, and Klyuchnik-backed
secret use. The narrow `RealEffectExecutor` additionally proves exact local
filesystem and loopback effects; it has no model-controlled OS path, endpoint,
HTTP path, or payload. Raw fake secret material stays in the broker;
provider-visible results preserve Niti/Metka or are payload-free receipts. No
generic executor, multi-language SDK, Streamable HTTP, cloud control plane, or
internet gateway exists in the current source surface; the Rust client and MCP
stdio adapter remain local carriers.

## Production runtime boundary

The runtime hardening layer adds `RuntimeService` and a loopback-only
`RuntimeListener` around the existing Gateway. Its four-byte length-prefixed
JSON frame is bounded before nested request decoding; strict fields carry a
bounded request ID, lifecycle ID, authentication proof, and Gateway DATA. The
authenticator is a trusted deployment input and is checked before lifecycle
admission, provider invocation, Krosna authorization, or protected effect.

Authentication is intentionally not authorization: it identifies the runtime
caller, while model proposals still use the fixed provider vocabulary and must
obtain a fresh Krosna-issued Propusk. Request/lifecycle IDs are consumed by a
bounded in-memory ledger, so duplicate/replayed IDs fail closed and an unknown
effect outcome cannot be retried automatically. The listener has no queue and
serves one connection at a time; existing Gateway/provider/effect budgets
remain the inner bounds.

`CancellationToken` is checked at Gateway lifecycle boundaries and before each
executor call. `shutdown()` stops new admission but does not claim to interrupt
an already blocking synchronous provider or OS call. Runtime receipts contain
only identities, categories, execution IDs, outcome, uncertainty, and bounded
effect summaries. If response encoding itself exceeds the transport budget, the
listener returns a terminal `ResponseTooLarge` failure with the bounded receipt
preserved, rather than suggesting retry. Debug/error surfaces redact output and
authentication data.

The listener is a local carrier, not a TLS implementation or process-isolation
mechanism. TLS termination, OS ACLs, job/container policy, core-dump policy,
secret injection, and durable distributed replay are deployment concerns. The
runtime threat model records those partial/out-of-model guarantees explicitly.

## Real OpenAI Responses adapter — v0.1 non-streaming boundary

`crates/tkach-provider-openai` is a thin provider adapter, not a second policy
kernel. `OpenAiConfig` is trusted host configuration: the API key is private,
redacted, and zeroized when configuration-owned storage is dropped; the
endpoint is HTTPS-only with no embedded credentials, query,
or fragment, and the model label is a bounded token. `ReqwestTransport` uses
rustls, a finite timeout, bounded response reads, and no redirects. Transport
errors are static and do not expose provider error bodies.

The adapter sends a strict Responses request with the fixed Tkach custom
function vocabulary, `store:false`, `background:false`,
`parallel_tool_calls:false`, and no conversation or `previous_response_id`
state. Built-in web/file/computer/MCP tools are not advertised. The response
parser accepts only bounded completed assistant text and known completed
function calls; unknown item types, duplicate fields, malformed statuses,
oversized values, and invalid JSON arguments fail closed. Function arguments
are intentionally the empty object, and the adapter reconstructs fixed raw
`ActionRequest` proposals rather than interpreting model-selected scopes.

Read-only tool results return as bounded `function_call_output` DATA items
paired with tracked call IDs. Response/call IDs are replay markers only and
are retained in a bounded provider lifecycle set. No ID creates authority.
The provider can stage text and proposals through the existing Gateway sink,
but cannot construct Decision/Propusk, call an executor, access Klyuchnik, or
release output. The real provider path is therefore still subject to the same
Krosna, Ruslo, Niti/Metka, and egress-Zaslon gates as hostile test doubles.

Responses streaming, provider-side tools, automatic retry, multi-language
SDKs, Streamable HTTP, and
production transport orchestration are not implemented in the current source
surface. The Gateway contract is synchronous and buffers security-relevant
output before release; no token-by-token release API exists in this baseline.

## Architecture pruning and product contract

The current product boundary is documented in `PRODUCT_CONTRACT.md`: Tkach is
a synchronous, bounded security kernel plus an in-process Gateway and a
non-streaming OpenAI adapter. Model/provider output is hostile DATA and can
only become a typed proposal; authority, information flow, secret use, and
release remain in the existing core/Gateway boundaries.

The A0-A20 review removed only three redundant public names: the zero-sized
`DataLane` marker, the empty `Klyuchnik` facade, and the `ScriptedProvider` alias.
The Gnezdo context, Klyuchnik broker, and `DeterministicProvider` are the actual
mechanisms. Krosna, Propusk, Ruslo, Zaslon, Klyuchnik broker, Gnezdo, Niti,
Metka, and Sled retain their documented roles. Repeated checks at Krosna,
Ruslo, Gateway, and the provider boundary are intentional trust-boundary
checks, not competing policy engines.

`INTEGRATION.md` defines Basic Gateway, Controlled Agent, Sealed Agent, Local
Authenticated Runtime, the narrow RealEffectExecutor profile, the local Rust
client carrier, and the MCP stdio carrier. The current source surface has no
configuration DSL, provider abstraction layer, streaming event model,
Streamable HTTP, or internet gateway.

## Current non-implemented surfaces

Anthropic, Streamable HTTP, cloud services, multi-language SDKs, dashboards, human approval services,
production gateway orchestration, TLS/process supervisor integration, and
generic executors are not part of this baseline. The runtime listener is a
narrow local frame boundary, not a claim of generic production readiness.
Future selection is governed by `ROADMAP.md`; these facts are not permanent
bans.

## Shape and dependency review

The repository keeps seven production crates with explicit ownership boundaries:
provider-independent core, Gateway orchestration/effects, the OpenAI provider
adapter, CLI onboarding, loopback HTTP transport, bounded Rust client, and MCP
stdio transport.
The excluded `fuzz` package is tooling, not a product crate. No policy
DSL, generic executor, multi-language provider SDK, or second policy engine is
needed by the current contract.

The earlier pruning review removed only vocabulary-only surface: the
zero-sized `DataLane` marker, empty `Klyuchnik` facade, and
`ScriptedProvider` alias. The real Gnezdo context, Klyuchnik broker,
`DeterministicProvider`, and all enforcement checks remain. The direct
`zeroize` dependency is retained where secret-bearing values are owned; its
use for broker storage and the runtime authenticator is a security boundary,
not convenience duplication. Transitive duplicate `syn` and `windows-sys`
versions remain because their upstream requirements differ; unsupported
convergence would increase supply-chain risk.
