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

## Mandate 7 — Diode directional information flow

- Architecture: typed `FlowRequest`, `FlowSource`, `FlowOperation`,
  `FlowMatcher`, and effect-ranked `Diode`; Krosna can compose it ahead of
  policy authorization.
- Security: read/export/reverse/onward edges are independent; unknown
  endpoints/operations fail closed; protected public export is a hard gate;
  tagged model flows copy Niti/Metka and cannot supply an arbitrary source or
  principal claim.
- Tests: 54 tests pass, including read-vs-export/reverse goldens, unknown
  destination, mixed-provenance route-laundering, classification property,
  deterministic conflict ordering, payload-free evidence, and Krosna/Diode
  composition.
- Weaknesses and hardening: public arbitrary flow source construction was found
  capable of metadata/route laundering; source construction was restricted to
  crate-private context mapping or fixed-Model tagged mapping, with regression
  coverage.
- Commit: `diode: enforce directional provenance-aware information flow`.

## Mandate 8 — Pechat opaque secret broker

- Architecture: Pechat exposes validated opaque `SecretHandle` values and
  keeps raw bytes in a private non-serializable broker value. Authorized
  `secret.use` requires a kernel-issued exact `Propusk`; raw reveal is denied.
- Security: handles, receipts, errors, and debug output contain no secret
  value. Duplicate and malformed handles fail closed, and a mismatched token
  is rejected before broker lookup.
- Tests: 60 tests pass, including model-visible handle checks, reveal denial,
  authorized mock use, Propusk mismatch, duplicate registration, and safe
  serialization/debug assertions.
- Weaknesses and hardening: a public broker method initially leaked a private
  secret type in its return signature; it was replaced with a payload-free
  unit error result before the full validation rerun.
- Commit: `pechat: isolate broker secrets behind opaque handles`.

## Mandate 9 — Sled and enforcement testbed

- Architecture: Sled records bounded trace-local decision IDs and typed
  payload-free evidence. The testbed models hostile typed proposals, routes
  authorized non-secret effects through `ProtectedExecutor`, and routes
  authorized `secret.use` through Pechat.
- Security: trace serialization and all testbed debug/receipt surfaces contain
  metadata only; oversized model input, trace exhaustion, missing Pechat, and
  token conversion mismatch fail closed.
- Tests: 67 tests pass, including monotonic/bounded traces, safe JSON,
  hostile DATA containment, canonical hostile-chain outcomes, exact denial
  reasons, executor boundary behavior, and broker-route isolation.
- Weaknesses and hardening: the initial hostile export fixture used a database
  resource with `network.send`, so Krosna correctly rejected it as unknown
  before Diode. The fixture was corrected to a typed network resource so the
  test now exercises Diode's default-deny path; missing-broker behavior also
  has explicit regression coverage.
- Commit: `sled: add safe evidence and hostile enforcement testbed`.

## Mandate 10 — Composition testing

- Architecture: independent integration scenarios combine Gnezdo, Zaslon,
  Krosna/Propusk, Diode, Niti/Metka, Pechat, Sled, and the fake executor.
  Scenarios cover hostile DATA, formal blocking, authorization, directional
  exfiltration, secret handles, mixed lineage, detector absence, and multiple
  simultaneous defense failures.
- Security: deterministic containment remains effective when the ingress
  detector is absent; only explicit allow produces an executor effect, while
  protected external export and secret reveal remain denied.
- Tests: 76 tests pass, including 9 independent composition/state-space tests
  and all prior unit/property/regression coverage.
- Weaknesses and hardening: the state-space test uses valid typed network
  resources and confirms protected external flows cannot be re-enabled by a
  wildcard allow policy.
- Commit: `composition: add adversarial Strong Core scenarios`.

## Mandate 11 — Core red team

- Attack surface reviewed: Krosna precedence and state conversion, Zaslon
  canonicalization/stream seams, Gnezdo authority isolation, Propusk scope,
  Niti/Metka propagation, Diode direction and provenance, Pechat isolation,
  Sled/error/debug redaction, malformed wire values, UNKNOWN states, resource
  matching, canonical paths, and race/TOCTOU assumptions.
- Reproduced and fixed weaknesses: Zaslon whitespace split across chunks;
  debug output exposing content, patterns, matcher tails, or generic payloads;
  untrusted principal spoofing; forged trusted `System` provenance; and empty
  derivations labeled `Public`. Each has an independent regression test.
- Fuzzing: `fuzz/` contains libFuzzer targets for `CanonicalText` and domain
  deserialization (`Provenance`, `ResourceScope`, `SecurityContext`). Both
  targets compile. A 100-run binary smoke attempt reached the Windows MSVC
  linker but could not execute because the linker reported a missing entry
  point; the existing proptest/property suite remains green.
- Tests and review: the prior unit/property suite and 9 composition tests pass
  after the hardening pass; rustfmt, clippy with warnings denied, and the
  dependency checks pass.
- Commit: `20d5f78` (`red-team: close identity lineage and logging bypasses`).

## Mandate 12 вЂ” Production-oriented core hardening

- Architecture: public untrusted roots no longer accept caller-supplied
  principal, provenance, or classification metadata; public tagged-data flows
  fix source to the model. Policy, Zaslon, Diode, provenance, derivation,
  model-fixture, Sled, Pechat, and stream state all have explicit bounds.
  `secret.use` is recognized only at the exact Pechat destination, and
  protected external flow denial applies to every flow operation.
- Security: red-team candidates for metadata relabeling, non-Export egress,
  incorrect `NetworkSend` source, generic secret-use execution, stream-size
  exhaustion, premature stream `Clear`, and oversized/malformed lineage were
  reproduced or reasoned through and closed. Intermediate Zaslon scans return
  `NeedMoreData`; only `finish()` can clear a non-empty stream.
- Tests and review: 93 unit tests and 9 independent composition tests pass;
  new regressions cover public metadata roots, public tagged-flow mapping,
  direct fake-executor secret rejection, all-operation protected egress, exact
  secret routing, bounded collections, and cumulative stream input. The fuzz
  targets compile; Windows MSVC cannot execute the libFuzzer binary because of
  a linker entry-point failure, while Linux CI runs the smoke target.
- Supply chain and CI: `cargo audit` and `cargo deny check` pass with pinned
  tool versions and an immutable checkout action reference in CI.
- Commit: `a59f693` (`hardening: bound inputs and close public metadata routes`).

## Strong Core Checkpoint

- Result: passed on 2026-09-10 after the M12 hardening cycle. All 60 checkpoint
  conditions are substantially satisfied for the implemented provider-
  independent core; owner review is now required before product expansion.
- Validation: `cargo fmt --all -- --check`, clippy with warnings denied,
  `cargo test --all --locked`, `cargo test --all --release --locked`, fuzz
  binary compile-check, `cargo audit`, and `cargo deny check` all pass.
- Security scan: the official Standard scan completed with 10 reviewed
  surfaces and no reportable findings. Its snapshot predates M12, so the
  report records post-scan source re-review and regression validation rather
  than claiming the scanner analyzed the later commit.
- Environment limitation: Windows MSVC cannot run the libFuzzer binary due to
  `LNK1561` missing entry point; the binaries compile and Linux CI runs the
  100-run smoke target.
- Final state: local commits only; no remote push was performed.
