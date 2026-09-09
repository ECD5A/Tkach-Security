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
