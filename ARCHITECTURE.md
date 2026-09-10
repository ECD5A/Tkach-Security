# Architecture

## Implemented baseline

The repository currently contains one provider-independent Rust workspace
member, `tkach-core`. The crate has an explicit domain module with validated
security types and a synchronous Krosna evaluator. It has no provider,
network, database, runtime, or external execution dependency.

Zaslon provides sorted, unique action hard-deny rules and formal content rules.
Its canonicalizer uses only ASCII lowercase and ASCII-space folding; controls,
non-ASCII (including zero-width and bidi), backslash escapes, and empty/oversize
values are rejected. Its streaming matcher retains a suffix so a forbidden
sequence cannot be bypassed by chunking. Zaslon reports ingress and egress
separately and can be installed ahead of Krosna policy.

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
context-to-Diode mapper is crate-private; public tagged-data flow mapping fixes
the source to the model. These restrictions prevent caller-controlled identity
or provenance metadata from becoming authority.

M12 adds explicit resource budgets before allocation or indexing: policy,
Zaslon, and Diode rules are bounded; provenance lineage and derivation parents
are bounded and canonicalized; model fixtures, Sled traces, Pechat entries,
secret values, and Zaslon stream input are bounded. A streaming Zaslon scan
returns `NeedMoreData` until explicitly finished, so an intermediate result is
never a release permission.

## Target Strong Core shape

```text
validated SecurityEnvelope
          |
          v
        Krosna
   /      |       \
Zaslon  Propusk  Diode
   \      |       /
      decision + Sled
          |
     Pechat boundary
```

Gnezdo contains untrusted content in a data lane. Niti and Metka preserve
provenance and conservative classification. No model output is trusted as
policy or authority. The protected executor boundary accepts only kernel-issued
authorization once that mandate is implemented.

## Trusted Computing Base

At the checkpoint, the TCB is intended to be the typed domain and synchronous
policy kernel in `tkach-core`, plus Rust's type/visibility rules. Policy and
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

Diode evaluates an explicit directed `FlowRequest` with source endpoint,
destination, flow operation, provenance, and classification. It has fixed effect
precedence and default denial; unknown endpoints/operations and protected
export to `PublicExternal` are denied. Public tagged-data mapping fixes the
source as `Model` and copies Niti/Metka, while Krosna's context mapper is
crate-private. Thus `READ` into model context is not an inferred `EXPORT`, and
reverse/onward edges require their own rules.

Pechat exposes only validated `SecretHandle` values to model-facing code. The
fake broker stores raw bytes in a private non-serializable `SecretValue`, bounds
entry/value capacity, accepts only a Krosna-issued exact `Propusk` for
`secret.use`, and refuses every reveal request. Receipts, errors, and debug
output contain no broker secret.

Sled records bounded, trace-local decision IDs alongside the existing typed
evidence and serializes only those payload-free records. The enforcement
testbed models hostile proposals, sends allowed non-secret effects through a
`ProtectedExecutor`, and routes an authorized secret-use effect through Pechat;
missing broker or token conversion fails closed.

Independent composition tests exercise Gnezdo, Zaslon, Propusk, Diode,
Niti/Metka, Pechat, and Sled together. They include detection-independent and
multiple-defense-failure scenarios; no heuristic result is treated as an
authority input.

## Future, not implemented

OpenAI, Anthropic, MCP, HTTP gateways, cloud services, SDKs, dashboards, and
human approval services are explicitly deferred until after owner review of the
Strong Core checkpoint.
