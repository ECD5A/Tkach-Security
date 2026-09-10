# Architecture Cost Review

This document records A7, A10, and A11 decisions. It is a sanity review of
complexity and integration surface, not a performance benchmark.

## Configuration surface

The secure common case requires only:

1. a validated Krosna policy;
2. ingress and egress Zaslon rules;
3. an optional Ruslo flow policy;
4. a release `Destination`;
5. a typed `ProtectedExecutor`;
6. an optional Klyuchnik broker for secrets;
7. trusted provider configuration such as `OpenAiConfig`.

These are typed Rust construction boundaries, not a new configuration DSL.
Defaults are conservative: unknown operations, destinations, classifications,
provider objects, and missing policy matches deny. Advanced customization stays
available to trusted host code without making the common integration learn all
internal types.

## Error model

Security distinctions remain structured internally, while integrators can map
them to a small contract vocabulary:

| Integrator class | Examples | Security meaning |
| --- | --- | --- |
| `ALLOW` | successful `GatewayResult` | Final flow/content gates passed; effects have crossed typed executor only |
| `DENY` | ingress/action/egress decision, invalid lifecycle, tool rejection | A policy, boundary, or ordering gate refused the operation |
| `INVALID` | malformed external request, unknown provider wire object, bad config | Input or configuration cannot safely enter the boundary |
| `FAILED` | provider failure, timeout, cancellation, trace/resource exhaustion | The lifecycle did not complete; no staged result or pending protected effect is released |

`GatewayErrorKind` and `SledTrace` retain more precise source-backed reasons
for operators. Provider and transport errors remain payload-free. Collapsing
these variants into one generic error would make safe remediation and denial
auditing harder, so no such merge is made.

## Complexity and buffering sanity

| Path | Dominant work | Security-mandated buffering/bound | Assessment |
| --- | --- | --- | --- |
| Krosna | Rule matching, sorted policy scan | Bounded rule count and typed request | Linear scan is deterministic and auditable |
| Ruslo | Rule matching over directed flow | Bounded flow-rule count | Separate pass is required to preserve flow semantics |
| Zaslon | Canonical input plus incremental matcher state | Aggregate pattern, chunk, and cumulative input limits | Incremental state avoids rule-sized suffix copying |
| Gnezdo/Niti/Metka | Bounded derivation and classification joins | Parent, lineage, and content limits | Copies preserve ownership and immutable metadata |
| Gateway lifecycle | Turns × actions × bounded inputs | Fixed turns, messages, actions, context, output, and trace budgets | `seen_actions` is intentionally quadratic only within a max-32 action turn |
| OpenAI wire | Serialize request / parse buffered response | Fixed body, item, ID, argument, history, and request limits | Buffering is required by the non-streaming no-partial-release contract |
| Sled | Append typed evidence | Fixed trace and receipt limits | Diagnostic work cannot grow without bound |

The remaining copies are boundary copies: they either establish ownership,
preserve immutable lineage, or prevent partial release. No repeated traversal
was identified whose removal would preserve both auditability and the current
security proof.
