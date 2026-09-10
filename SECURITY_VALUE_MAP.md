# Security Value Map

This map distinguishes real enforcement from supporting state, diagnostics,
and integration infrastructure. It is the A12 architectural evidence table.

| Component | Threat | Invariant | Enforcement point | Failure if removed | Category |
| --- | --- | --- | --- | --- | --- |
| Krosna | Model or caller requests an unauthorized effect | Only deterministic policy can authorize a typed action | `Krosna::evaluate` / `authorize`; hard-deny and default-deny ordering | Unauthorized action can become a `Propusk` | Required enforcement |
| Propusk | Raw request reaches an executor or scope is widened | Execution requires a kernel-issued exact-scope authority | Private `AuthorizedAction` construction and `ProtectedExecutor::execute` | Caller can invoke protected effects without proof of authorization | Required enforcement |
| Ruslo | Protected data is exported or a direction is confused | READ, EXPORT, and TRANSFER are separate directed decisions | `Ruslo::evaluate` plus Gateway final flow gate | Protected-derived output can cross an allowed-looking public route | Required enforcement |
| Zaslon | Formal blocked content/action is smuggled through normalization or chunks | Configured formal representation is denied consistently and streams finish explicitly | Canonical matcher, action rules, `ZaslonStream` | Rule bypass or premature/partial release becomes possible | Required enforcement |
| Klyuchnik broker | Model sees or reveals raw credential material | Secrets stay broker-side; use requires exact route and reveal is denied | `SecretHandle`, `SecretBroker`, exact `secret.use` Krosna route | Raw secret disclosure or uncontrolled secret use | Required enforcement |
| Gnezdo | Instructions/data impersonate trusted control | Untrusted content is DATA/None/Untrusted and cannot promote itself | `Gnezdo::contain`, validated `SecurityContext`, absent public promotion | Prompt injection can become authority by representation change | Required security state |
| Niti | Derived output loses source lineage | Every supported derivation retains bounded parent provenance | `Provenance::derived_from`, `Niti`, `TaggedData` | Ruslo and diagnostics can no longer distinguish protected origin | Supporting security state |
| Metka | Model or transformation lowers sensitivity | Classification join is monotonic; declassification needs trusted permit | `Metka::join`, `TaggedData`, private permit issuance | Protected data can be relabeled public | Supporting security state |
| Sled | Denials/effects become unauditable or logs leak payloads | Evidence is bounded, typed, payload-free, and not authority | `SledTrace` records kernel `Decision` only | Integration failures lose explainability or developers add unsafe logging | Diagnostic |
| Gateway | Provider failure, batch ordering, or output path bypasses Core | Stage first, authorize all, execute in order, release last | `Gateway::run`, lifecycle state, staging and final gates | Partial protected effects or unvetted output can escape | Required integration infrastructure |
| OpenAI adapter | Hostile provider wire data or credential routing bypasses Gateway | Provider data maps only to bounded proposals and trusted transport config | Strict wire parser, bounded transport, fixed tools, replay checks | Unknown provider objects or credentials can cross the adapter boundary | Supporting integration infrastructure |

## Composition conclusion

The minimum physical enforcement core is Krosna + Propusk + Ruslo + Zaslon +
Klyuchnik's broker boundary. Gnezdo, Niti, and Metka are not redundant labels:
they carry different state consumed by those gates. Sled is not an enforcement
primitive, but removing it would make safe integration and deny diagnosis
meaningfully weaker. Gateway and the OpenAI adapter are integration boundaries,
not alternate policy engines.

The map supports the three API-pruning removals in
`PRIMITIVE_REVIEW.md`; none of those removals deletes a row above.
