# Development Record

## Mandate 0 — Foundation and security baseline

- Architecture: one provider-independent `tkach-core` crate; synchronous core;
  no network, database, provider SDK, or runtime.
- Security: `unsafe_code` is forbidden; the model is not a trusted authority;
  documentation separates intended guarantees from assumptions and limits.
- Tests: `cargo fmt --check`, clippy with warnings denied, and `cargo test --all`
  pass (the first dependency fetch required the approved network-enabled Cargo
  run).
- Weaknesses and hardening: implementation primitives are intentionally not
  present yet; subsequent mandates must add executable invariant coverage.
- Commit: `foundation: establish Strong Core repository baseline`.

## Mandate 1 — Strong security domain model

- Architecture: validated identifier newtypes, explicit principal/authority/
  trust/lane/provenance/classification/resource/scope/destination/capability/
  request/context/decision types; raw `ActionRequest` carries no permit.
- Security: model cannot be trusted control; data/control combinations are
  validated; generic IDs reject controls, whitespace, and path traversal;
  deserialization re-runs context and provenance invariants; Sled evidence has
  controlled payload-free reason codes.
- Tests: 9 tests pass, including property tests for identifier validation and
  classification join, serialization round-trip, forged context rejection,
  lineage preservation, and exact-scope isolation.
- Weaknesses and hardening: a first review found automatic deserialization could
  bypass invariants and path-like IDs could be ambiguous; custom validated
  deserializers and segment checks were added with regression tests.
- Commit: `domain: establish typed security domain model`.

## Mandate 2 — Krosna deterministic kernel

- Architecture: typed policy/rule/matcher representation; explicit rule IDs;
  fixed effect precedence; stable ID tie-break; synchronous evaluation; policy
  loading and evaluation are separate from external persistence.
- Security: unknown operations/destinations, control-sensitive model actions,
  principal mismatch, policy failure, and protected public export fail closed;
  allow rules cannot override deny or hard gates; decisions always carry
  payload-free Sled evidence.
- Tests: 20 tests pass, including deterministic conflict order, hard-deny
  precedence, duplicate-policy serde rejection, policy-failure denial,
  unknown-state denial, protected export, and model authority gates.
- Weaknesses and hardening: initial policy deserialization was reviewed for
  validation bypass and now re-enters `Policy::new`; a failed policy state is
  intentionally non-executable and cannot be interpreted as allow.
- Commit: `krosna: implement deterministic fail-closed policy evaluation`.

## Mandate 3 — Zaslon hard-deny enforcement

- Architecture: Zaslon owns explicit action hard-deny and formal ingress/egress
  content rules; canonical text and stateful stream matching are separate from
  semantic detection. Krosna can install Zaslon before policy evaluation.
- Security: strict ASCII canonicalization rejects controls, non-ASCII/zero-width
  and bidi characters, backslash escapes, malformed/empty/oversized values;
  sorted unique rule IDs and sticky stream blocks make precedence and chunk
  behavior deterministic.
- Tests: 27 tests pass, including canonicalization adversarials, direction
  isolation, cross-chunk matching, malformed-input fail-closed, duplicate rule
  rejection, payload-free evidence, and policy-vs-Zaslon integration.
- Weaknesses and hardening: review identified the need to prove the installed
  Zaslon is consulted before an explicit policy allow; the integration
  regression test now asserts the Zaslon rule ID and hard-deny reason.
- Commit: `zaslon: add canonical hard-deny boundaries and stream safety`.

## Mandate 4 — Gnezdo data/control containment

- Architecture: `UntrustedContent` is a model-readable DATA-lane value;
  `DataLane` exposes no authority or direction; `TrustedControl` is opaque and
  has no public constructor. Derived data is explicit and lineage-preserving.
- Security: web/document-like imperative text remains data, cannot promote
  itself, cannot mint control, and cannot be reconstructed from arbitrary wire
  state; content is bounded without echoing payloads in errors.
- Tests: 30 tests pass, including hostile web injection containment, nested
  derived lineage/classification, promotion denial, bounded-content error
  behavior, and data-lane invariants.
- Weaknesses and hardening: review found that even crate-private trusted
  construction was unused and could become an accidental authority path; it was
  removed, leaving trusted control unconstructible until a later kernel-issued
  primitive is introduced.
- Commit: `gnezdo: isolate untrusted data from control authority`.

## Mandate 5 — Propusk scoped authorization

- Architecture: canonical exact/prefix `ResourceScope`; known capability
  registry; `Krosna::authorize`; private `CapabilityGrant` and
  `AuthorizedAction`; `ProtectedExecutor` accepts only the `Propusk` alias.
- Security: unknown capabilities fail closed; principal/operation/capability/
  scope are bound into the token; broad policy matching cannot widen the issued
  exact resource token; path lookalikes, traversal, malformed wire scopes, raw
  requests, and incoherent internal grants are rejected.
- Tests: 38 tests pass, including authorize-only-after-allow, unknown-capability
  denial under wildcard policy, prefix child/lookalike scope checks, executor
  type boundary, and incoherent grant rejection.
- Weaknesses and hardening: a fixture mismatch exposed that strict capability
  validation was correctly denying a stale `file.read`/resource pair; the
  fixture was corrected and the generated non-security proptest artifact was
  removed.
- Commit: `propusk: enforce scoped kernel-issued execution authority`.

## Mandate 6 — Niti and Metka

- Architecture: immutable `Niti`, `Metka`, and generic `TaggedData<T>` wrappers;
  derivation is explicit and joins parent lineage/classification.
- Security: known lineage cannot be stripped through Niti decode; mixed model
  output inherits the highest parent class; self-declassification is always
  denied; lowering is possible only through an opaque trusted permit with no
  public issuer.
- Tests: 43 tests pass, including mixed public/secret derivation, lineage
  preservation, forged Niti wire rejection, trusted-permit target checks, and
  independent classification monotonicity property testing.
- Weaknesses and hardening: review confirmed tagged payloads are serialize-only
  and that declassification cannot be reached through model-facing APIs; the
  empty-parent path remains conservative (`Unknown` + `Derived`).
- Commit: `niti-metka: preserve lineage and conservative classification`.
