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

## Strong Core Checkpoint — Candidate #1 historical

- Result: Candidate #1 passed on 2026-09-10 after the M12 hardening cycle. The
  checkpoint was intentionally re-opened for Strong Core Hardening Round 2.
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

## Strong Core Hardening Round 2

- Scope: local hardening on the frozen `strong-core-candidate-1` tag at
  `7d555cb`; no provider, MCP, SDK, gateway, UI, cloud, or integration work.
- Design and fixes: action-to-Diode mapping now treats every model-controlled
  non-read effect as model-originated; the fake protected executor rejects any
  direct `SecretBroker` destination; and `ZaslonStream` is terminal after a
  successful finish. A misleading composition helper was corrected so its
  oracle no longer pretended to vary classification.
- Independent tests: the crate now has 104 unit tests, 9 composition tests,
  and 9 independent integration-oracle tests. In-crate truth tables cover
  authority/lane, capability/scope, classification/destination, direction,
  secret handles, unknown states, public APIs, exact bounds, and malformed wire
  values. Integration tests independently exercise public construction paths.
- Mutation testing: `cargo mutants --package tkach-core --jobs 1 --no-times`
  completed 426 mutants with 293 caught, 132 unviable, and one equivalent
  survivor. The survivor replaces `Zaslon::empty()` with `Default::default()`;
  `Zaslon` derives `Default`, so the behavior is identical. Earlier semantic
  survivors for bounded strings, capability recognition, secret redaction, and
  route conditions were closed with direct tests and rerun successfully.
- Public API review: no public constructor mints trusted authority, a
  `Propusk`, a secret value, or an arbitrary flow source. Public model roots
  normalize to conservative metadata; tagged-data flows fix source to Model;
  broker values remain private and non-serializable.
- Residual risks: model-readable generic serialization is not an egress permit;
  adapters must run Diode/Zaslon before external release. Sled evidence is
  bounded typed metadata, not raw payload, but hostile-model trace exposure can
  remain a metadata side channel. Windows MSVC cannot execute the libFuzzer
  binary because of the known linker entry-point limitation; Linux CI retains
  the smoke target.
- Security scan: the Round 2 Standard Security Scan was launched with id
  `9f1895db-2b61-466c-b1c2-fb898567643e`; its last observed state was still
  preflight with zero findings, so it is not represented as a completed scan.
- Commit: recorded after the complete validation gate for this round.

## Strong Core Final Hardening Round 3

- Scope: final adversarial hardening from Candidate #2 `bf59b24`; no OpenAI,
  Anthropic, MCP, SDK, gateway, UI, cloud, or product integration work.
- Defects reproduced and fixed: request-controlled Sled identifiers could be
  serialized as diagnostic payloads; public `Decision`/evidence/receipt APIs
  could create authority-shaped artifacts; Niti serialization did not round-trip;
  declassification accepted `ResourceKind::Unknown`; FakeBroker lacked an
  aggregate secret-byte budget; and Zaslon copied matcher suffixes per chunk,
  creating a quadratic CPU path.
- Hardening: Sled evidence now uses payload-free categories, Decision creation
  and Sled recording are kernel-internal, receipts expose accessors only, Niti
  uses an explicit wrapper wire shape, unknown declassification resources fail
  closed, Pechat has a 16 MiB aggregate fake-broker budget, and Zaslon uses
  incremental prefix matching with a 256 KiB aggregate pattern budget.
- Regression/adversarial coverage: hostile metadata markers are absent from Sled
  JSON; receipt and Propusk deserialization/forgery paths are unavailable;
  Niti round-trip, unknown-resource, aggregate-budget, canonicalization
  idempotence, failed-effect, and stream-boundary tests pass.
- Current local test counts after Round 3 changes: 112 unit tests, 9 composition
  tests, and 9 independent integration-oracle tests.
- Residual assumptions: policy `RuleId` is trusted validated configuration and
  remains in evidence for explainability; Pechat handle existence can be
  observable to an already-authorized caller. No constant-time claim is made.
- The final validation matrix, mutation result, freeze commit, and freeze tag
  are recorded below when the round is complete. Local history only; no push.

## Gateway Phase 1 — Mandate G0

- Scope: separate threat model for an in-process, synchronous, provider-
  independent gateway around the frozen Strong Core. No OpenAI, Anthropic, MCP,
  SDK, HTTP, cloud, or production provider integration.
- Architecture: the gateway will own bounded ingress, request lifecycle,
  provider orchestration, output staging, and tool dispatch. Krosna, Diode,
  Zaslon, Gnezdo, Propusk, Pechat, Niti, Metka, and Sled remain the authority
  and evidence boundaries; the gateway must not duplicate their semantics.
- Invariant: `NO PROTECTED EFFECT OR PROTECTED EGRESS MAY BYPASS TKACH
  ENFORCEMENT`.
- Threat model: `GATEWAY_THREAT_MODEL.md` records source-backed boundaries,
  hostile-provider assumptions, planned budgets, attack paths, and unresolved
  deployment questions. It explicitly distinguishes planned controls from
  implemented Strong Core controls.
- Review limitation: independent delegated architecture review was unavailable;
  the threat model was reviewed sequentially against the current source.
- Commit: recorded below after the G0 documentation diff review.

## Gateway Phase 1 — G1-G10 implementation and red team

- Architecture: committed `tkach-gateway` as a separate provider-independent
  crate. The gateway owns strict bounded JSON ingress, Gnezdo/Zaslon ingress,
  private SecurityEnvelope construction, provider lifecycle, staged output,
  Krosna/Diode/Zaslon egress, and Propusk-only tool dispatch. Core primitives
  remain the authority and no client tool declaration changes the fixed tool
  catalog.
- Security: provider output is untrusted text and typed proposals only. It has
  no executor, broker, Propusk, Decision, trusted provenance, declassification,
  or release API. Final output is fully gated before actions execute; an
  egress-denied response therefore cannot leave an authorized write behind.
  Awaited turns allow reads only, all action proposals are preflighted, and
  duplicate proposals are rejected within a lifecycle. Invalid release
  destinations, parser ambiguity, raw/body and collection limits, provider
  failure/timeout/cancellation, chunk/stream limits, malformed steps, Pechat
  reveal, protected public export, metadata stripping, and fake-provider
  authority claims fail closed.
- Tools and secrets: fake protected read/write/external-send/harmless-read and
  Pechat-backed secret-use routes are available only through kernel-issued
  Propusk. Tool data retains Niti/Metka; receipts and traces carry no raw
  secret. `FakeToolBroker` has a bounded effect log and never exposes its
  broker value to a provider.
- Tests: 14 Gateway boundary tests cover ingress, limits, fixed catalog,
  canonical hostile read-then-exfiltration, Niti/Metka preservation, egress
  stripping and stream seams, partial-effect regression, action preflight,
  Pechat reveal/use, provider malformed/timeout/failure/cancellation, replay,
  invalid release, and duplicate metadata. `fuzz/gateway_wire.rs` exercises
  arbitrary bounded JSON parser input. Workspace tests, clippy with warnings
  denied, and fuzz target compile-check pass.
- Defect found and fixed during self-attack: the first action lifecycle could
  execute a write before a later final egress gate failed. Final output flow
  and content validation now precede action execution, with a regression test.
- Defect found and fixed during the metadata/provenance attack: final output
  derivation initially considered protected tool parents but omitted the
  initial untrusted external inputs. A public tool result could then make a
  mixed output look public. Every provider input is now projected into the
  conservative Niti/Metka derivation, and a public-egress laundering regression
  test covers the path.
- Review limitation: independent delegated security workers were unavailable;
  the parent performed a source-backed sequential diff review and recorded the
  limitation in the Gateway threat model.
- Commit: recorded below after the Gateway Phase 1 checkpoint.
