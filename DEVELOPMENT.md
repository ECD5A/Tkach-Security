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

- Architecture: `UntrustedContent` is a model-readable DATA-lane value whose
  validated context exposes no authority or direction; `TrustedControl` is
  opaque and has no public constructor. Derived data is explicit and
  lineage-preserving.
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

## Mandate 7 — Ruslo directional information flow

- Architecture: typed `FlowRequest`, `FlowSource`, `FlowOperation`,
  `FlowMatcher`, and effect-ranked `Ruslo`; Krosna can compose it ahead of
  policy authorization.
- Security: read/export/reverse/onward edges are independent; unknown
  endpoints/operations fail closed; protected public export is a hard gate;
  tagged model flows copy Niti/Metka and cannot supply an arbitrary source or
  principal claim.
- Tests: 54 tests pass, including read-vs-export/reverse goldens, unknown
  destination, mixed-provenance route-laundering, classification property,
  deterministic conflict ordering, payload-free evidence, and Krosna/Ruslo
  composition.
- Weaknesses and hardening: public arbitrary flow source construction was found
  capable of metadata/route laundering; source construction was restricted to
  crate-private context mapping or fixed-Model tagged mapping, with regression
  coverage.
- Commit: `ruslo: enforce directional provenance-aware information flow`.

## Mandate 8 — Klyuchnik opaque secret broker

- Architecture: Klyuchnik exposes validated opaque `SecretHandle` values and
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
- Commit: `klyuchnik: isolate broker secrets behind opaque handles`.

## Mandate 9 — Sled and enforcement testbed

- Architecture: Sled records bounded trace-local decision IDs and typed
  payload-free evidence. The testbed models hostile typed proposals, routes
  authorized non-secret effects through `ProtectedExecutor`, and routes
  authorized `secret.use` through Klyuchnik.
- Security: trace serialization and all testbed debug/receipt surfaces contain
  metadata only; oversized model input, trace exhaustion, missing Klyuchnik, and
  token conversion mismatch fail closed.
- Tests: 67 tests pass, including monotonic/bounded traces, safe JSON,
  hostile DATA containment, canonical hostile-chain outcomes, exact denial
  reasons, executor boundary behavior, and broker-route isolation.
- Weaknesses and hardening: the initial hostile export fixture used a database
  resource with `network.send`, so Krosna correctly rejected it as unknown
  before Ruslo. The fixture was corrected to a typed network resource so the
  test now exercises Ruslo's default-deny path; missing-broker behavior also
  has explicit regression coverage.
- Commit: `sled: add safe evidence and hostile enforcement testbed`.

## Mandate 10 — Composition testing

- Architecture: independent integration scenarios combine Gnezdo, Zaslon,
  Krosna/Propusk, Ruslo, Niti/Metka, Klyuchnik, Sled, and the fake executor.
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
  Niti/Metka propagation, Ruslo direction and provenance, Klyuchnik isolation,
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
  fix source to the model. Policy, Zaslon, Ruslo, provenance, derivation,
  model-fixture, Sled, Klyuchnik, and stream state all have explicit bounds.
  `secret.use` is recognized only at the exact Klyuchnik destination, and
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
- Design and fixes: action-to-Ruslo mapping now treats every model-controlled
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
  adapters must run Ruslo/Zaslon before external release. Sled evidence is
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
  closed, Klyuchnik has a 16 MiB aggregate fake-broker budget, and Zaslon uses
  incremental prefix matching with a 256 KiB aggregate pattern budget.
- Regression/adversarial coverage: hostile metadata markers are absent from Sled
  JSON; receipt and Propusk deserialization/forgery paths are unavailable;
  Niti round-trip, unknown-resource, aggregate-budget, canonicalization
  idempotence, failed-effect, and stream-boundary tests pass.
- Current local test counts after Round 3 changes: 112 unit tests, 9 composition
  tests, and 9 independent integration-oracle tests.
- Residual assumptions: policy `RuleId` is trusted validated configuration and
  remains in evidence for explainability; Klyuchnik handle existence can be
  observable to an already-authorized caller. No constant-time claim is made.
- The final validation matrix, mutation result, freeze commit, and freeze tag
  are recorded below when the round is complete. Local history only; no push.

## Gateway Phase 1 — Mandate G0

- Scope: separate threat model for an in-process, synchronous, provider-
  independent gateway around the frozen Strong Core. No OpenAI, Anthropic, MCP,
  SDK, HTTP, cloud, or production provider integration.
- Architecture: the gateway will own bounded ingress, request lifecycle,
  provider orchestration, output staging, and tool dispatch. Krosna, Ruslo,
  Zaslon, Gnezdo, Propusk, Klyuchnik, Niti, Metka, and Sled remain the authority
  and evidence boundaries; the gateway must not duplicate their semantics.
- Invariant: `NO PROTECTED EFFECT OR PROTECTED EGRESS MAY BYPASS TKACH
  ENFORCEMENT`.
- Threat model: `GATEWAY_THREAT_MODEL.md` records source-backed boundaries,
  hostile-provider assumptions, planned budgets, attack paths, and unresolved
  deployment questions. It explicitly distinguishes planned controls from
  implemented Strong Core controls.
- Review limitation: independent delegated architecture review was unavailable;
  the threat model was reviewed sequentially against the current source.
- Commit: `59a0903` (`gateway: establish phase 1 threat model`).

## Gateway Phase 1 — G1-G10 implementation and red team

- Architecture: committed `tkach-gateway` as a separate provider-independent
  crate. The gateway owns strict bounded JSON ingress, Gnezdo/Zaslon ingress,
  private SecurityEnvelope construction, provider lifecycle, staged output,
  Krosna/Ruslo/Zaslon egress, and Propusk-only tool dispatch. Core primitives
  remain the authority and no client tool declaration changes the fixed tool
  catalog.
- Security: provider output is untrusted text and typed proposals only. It has
  no executor, broker, Propusk, Decision, trusted provenance, declassification,
  or release API. Final output is fully gated before actions execute; an
  egress-denied response therefore cannot leave an authorized write behind.
  Awaited turns allow reads only, all action proposals are preflighted, and
  duplicate proposals are rejected within a lifecycle. Invalid release
  destinations, parser ambiguity, raw/body and collection limits, provider
  failure/timeout/cancellation, chunk/stream limits, malformed steps, Klyuchnik
  reveal, protected public export, metadata stripping, and fake-provider
  authority claims fail closed.
- Tools and secrets: fake protected read/write/external-send/harmless-read and
  Klyuchnik-backed secret-use routes are available only through kernel-issued
  Propusk. Tool data retains Niti/Metka; receipts and traces carry no raw
  secret. `FakeToolBroker` has a bounded effect log and never exposes its
  broker value to a provider.
- Tests: 20 Gateway boundary tests cover ingress, limits, fixed catalog,
  canonical hostile read-then-exfiltration, Niti/Metka preservation, egress
  stripping and stream seams, partial-effect regression, action preflight,
  Klyuchnik reveal/use, provider malformed/timeout/failure/cancellation, replay,
  invalid release, and duplicate metadata. `fuzz/gateway_wire.rs` exercises
  arbitrary bounded JSON parser input. Workspace tests, clippy with warnings
  denied, and fuzz target compile-check pass.
- Mutation testing: `cargo mutants --package tkach-gateway --jobs 1
  --no-times` tested 296 mutants on the final Gateway source; 162 were caught,
  71 missed, and 63 were unviable. Manual review classified the remaining
  misses as diagnostic/accessor coverage gaps or fake-executor guards already
  constrained by the Propusk/Krosna boundary; no reportable security bypass
  survived the attack-path review.
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
- Commits: `1e1d16c` (Gateway boundary), `36ce4f7` (provenance/lifecycle
  hardening), and `9026605` (dependency-version packaging hardening).

## Gateway Hardening 1.5

- Scope: harden the frozen provider-independent Gateway boundary before any
  real provider adapter. No provider SDK, MCP, cloud, network transport, or
  UI was added.
- Lifecycle: `tkach-gateway/src/gateway.rs` now owns an internal fail-closed
  state machine: Received -> Validated -> Contained -> ProviderRunning ->
  OutputStaged -> EgressApproved -> ActionsEvaluated -> EffectsCommitted ->
  Released. Awaited read-only turns return to ProviderRunning; invalid skips,
  replay, cancellation, timeout, and provider errors never release output.
- Effect ordering: authorization is now separate from execution. All action
  proposals are preflighted before any executor call; final output flow and
  content gates run before a complete turn can execute. Phase 1 explicitly
  uses staged-effects semantics with no rollback claim and at most one
  irreversible non-read action per turn. Multiple writes and read-plus-denied-
  write batches fail before execution.
- Budget hardening: `ExternalRequest::new` now enforces the same aggregate
  request envelope as JSON input, with explicit message, metadata, and tool
  component sums. Exact/next-byte tests cover model context, tool results,
  owned-string deserialization, staging, final-output size, and collection
  boundaries.
- Tool boundary hardening: the fake executor checks the exact storage route;
  focused negative permit tests cover wrong identifiers and destinations.
  Coupled malformed read/network/secret shapes are separately proven unable
  to obtain a public Propusk through Krosna.
- Cancellation: timeout/cancelled provider responses discard staged actions;
  a second-turn failure after a read leaves only a non-irreversible read in
  evidence and creates no write, send, secret use, or release.
- Independent oracle: `gateway_boundary.rs` contains a separate lifecycle and
  terminal-effect oracle that does not call production transition code.
- Mutation testing: final `cargo mutants --package tkach-gateway --jobs 1
  --no-times` tested 319 mutants: 221 caught, 67 unviable, and 31 missed.
  All 31 survivors were classified individually in
  `GATEWAY_HARDENING_1_5.md`: 17 `DIAGNOSTIC_ONLY`, 13
  `UNREACHABLE_BY_PUBLIC_API` or equivalent defense-in-depth route guards,
  and one `EQUIVALENT` dispatch guard. There are no unexplained
  security-relevant survivors.
- Commit/tag: `gateway: harden lifecycle and staged effects`; local tag
  `gateway-v0.1`.

## Real Provider Phase v0.1 — Mandate P0

- Scope: begin the first real-provider phase with an OpenAI Responses API
  boundary. Anthropic, MCP, SDK, UI, cloud, and production gateway transport
  remain out of scope.
- Architecture: `OPENAI_PROVIDER_THREAT_MODEL.md` records the source-backed
  Client → Gateway → adapter → OpenAI → adapter → Gateway boundary. OpenAI
  output is model data only; response IDs, call IDs, metadata, and model
  authority claims are opaque and never become Tkach authority.
- Security invariants: provider output cannot mint Propusk, access an
  executor/Klyuchnik broker, alter Krosna/Zaslon/Ruslo policy, strip Niti/Metka,
  or bypass final egress gates. The planned adapter must use explicit
  `store:false`, no background/conversation state, no provider-side tools, and
  trusted HTTPS-only endpoint configuration.
- Review limitation: the threat model was reviewed sequentially because
  delegated architecture workers were unavailable.
- Commit: recorded with the P0 threat-model milestone.

## Real Provider Phase v0.1 — P1-P8 non-streaming OpenAI adapter

- Scope: implement the first real provider boundary without changing Strong
  Core policy semantics or adding SDK/MCP/UI/cloud/production gateway code.
- Configuration: `OpenAiConfig` validates trusted HTTPS endpoint/model/timeout
  values and keeps `OPENAI_API_KEY` private, redacted, and absent from public
  errors. `ReqwestTransport` uses rustls, finite timeout, no redirects, and a
  128 KiB bounded reader for both success and error bodies.
- Wire contract: `ResponsesRequest` emits only the fixed five Tkach custom
  functions, strict empty-object schemas, `store:false`, `background:false`,
  and `parallel_tool_calls:false`. It does not use provider conversations,
  previous response IDs, built-in tools, or MCP.
- Response contract: strict bounded parsing accepts completed assistant text
  and known completed function calls only. Unknown item types, duplicate
  fields, incomplete/failed statuses, oversized values, malformed JSON, and
  non-empty function arguments fail closed. Provider/call IDs are bounded
  replay markers and tool outputs are explicitly paired as DATA.
- Gateway composition: the actual `OpenAiProvider` path was run through a
  real Gateway test. `harmless_read` executed only after Krosna/Ruslo
  authorization and returned a bounded follow-up result; `external_send` was
  denied before the executor. A malformed oversized follow-up regression test
  confirmed pending call state is preserved after rejection.
- Fixtures/fuzzing: tracked normal, function-call, unknown-item, duplicate,
  incomplete, malicious-argument, and provider-error fixtures were added.
  `fuzz/openai_response` compiles with the existing libFuzzer targets.
- Live testing: `tests/live.rs` is explicit opt-in via
  `TKACH_LIVE_OPENAI_TESTS=1`; default test runs make no network call.
- Deliberate boundary: Responses streaming is not implemented because the
  current Gateway contract is synchronous and buffered. Adding a network
  streaming path without a corresponding secure Gateway event contract would
  expand the attack surface without increasing verified capability.
- Adversarial review: strict parser, credential, redirect, replay, transport,
  tool-result lineage, and real-Gateway authorization tests pass. The initial
  pending-call drain weakness found during self-review was fixed before commit.
- Commit: `a8d67dd Add bounded OpenAI Responses provider adapter`.

## Real Provider Phase v0.1 — mutation hardening cycle

- Expanded the provider suite to 33 all-feature unit tests with exact budget
  boundaries, duplicate/replay capacity, follow-up cardinality/history, UTF-8
  chunk seams, credential/endpoint limits, local bounded HTTP readers, and a
  TLS-failure transport test.
- Mutation run: `cargo mutants --package tkach-provider-openai
  --all-features --jobs 1 --no-times` tested 201 mutants: 158 caught, 29
  unviable, 1 timeout, and 13 missed. The missed set is limited to the
  non-authority `Debug`/`Display`/Serde `expecting` diagnostics, a private
  fixed-catalog guard unreachable through the public `ProviderRequest` API,
  a capacity-only allocation change, and the mathematically equivalent
  `stage_text` boundary guard. The timeout was the intentionally hostile
  nonterminating arithmetic mutant. No unexplained security-relevant survivor
  remains.
- Fuzz hook is covered under `--all-features`; the OpenAI response target
  returns only parser acceptance and cannot create a network client.
- Dependency gates: `cargo audit --no-fetch` reports no advisories. `cargo
  deny check` passes advisories, bans, licenses, and sources after explicitly
  allowing the ISC, BSD-3-Clause, and CDLA-Permissive-2.0 licenses required by
  the selected rustls dependency chain; duplicate `syn`/`windows-sys`
  versions remain warnings only.
- Hardening commit: `60835a2 Harden OpenAI provider boundaries under mutation
  review`.
- Dependency-policy follow-up: `359b734 Align dependency license policy with
  rustls`.
- Automated Codex Security diff scan was unavailable because its runner
  rejected the repository as lacking a resolvable HEAD; the parent therefore
  completed a source-backed sequential diff review, `git diff --check`, and
  explicit credential/redirect/parser/replay/authority checks.

## Architecture Pruning & Product Contract Review A0-A20

- Scope: simplify the product surface after `openai-provider-v0.1` without
  adding providers, MCP, streaming, SDKs, UI, cloud integration, production
  transport, or new security primitives. The product contract is frozen in
  `PRODUCT_CONTRACT.md`; the integration flow and Basic/Controlled/Sealed
  profiles are in `INTEGRATION_MODEL.md`.
- Primitive review: `PRIMITIVE_REVIEW.md` and `SECURITY_VALUE_MAP.md` assign a
  threat and enforcement role to Krosna, Propusk, Ruslo, Zaslon, Klyuchnik,
  Gnezdo, Niti, Metka, Sled, Gateway, and the OpenAI boundary. Repeated checks
  at independent trust boundaries are retained deliberately.
- Safe pruning: removed the zero-sized `DataLane` marker, empty `Klyuchnik`
  facade, and `ScriptedProvider` alias. No authority constructor, policy
  decision, flow rule, secret broker operation, lifecycle transition, or
  diagnostic invariant was removed. `SIMPLIFICATION_RED_TEAM.md` records the
  hostile attempts and expected denials.
- Dependency and cost review: removed a duplicate `serde_json` dev-dependency
  declaration; no runtime dependency or policy engine was added. Complexity,
  error mapping, and public-boundary decisions are in
  `ARCHITECTURE_COST_REVIEW.md` and `DEPENDENCY_REVIEW.md`.
- Measured result: 21 production Rust files remain; production Rust LOC fell
  from 12,966 to 12,904; approximate public declaration/field lines fell from
  372 to 364; unique direct normal dependency names remain 7. The exact
  before/after record is `PRUNING_METRICS.md`.
- Security review: the repository-wide Standard Security Scan found no
  reportable findings on its frozen source snapshot. It used parent-only
  review with partial coverage because generated artifacts were excluded;
  this limitation is explicit in the final report. The pruning range also
  receives a source-backed diff review and `git diff --check`.
- Final checkpoint: `PRODUCT_CONTRACT_CHECKPOINT.md` is the A20 checklist.
  It passed on the unchanged pruning code at `a64dad0` after the final
  debug/release test matrix, clippy, audit, deny, fuzz compile check,
  source-backed diff review, and clean worktree check. The automated
  pruning-range diff runner remained unavailable
  despite a valid clean non-bare HEAD and is recorded as a limitation rather
  than a false PASS.

## Product Proof B0-B22

- Scope: prove utility and security value of the frozen Strong Core, Gateway,
  and OpenAI boundary in an offline bounded environment. No new primitive,
  provider, MCP, Anthropic, streaming, SDK, UI, cloud, or production
  transport work was introduced.
- Design: `SECURITY_UTILITY_BENCHMARK.md` defines typed workload contracts and
  metrics. `crates/tkach-gateway/tests/product_proof.rs` supplies deterministic
  providers, an independent minimal unsafe reference, paired legitimate and
  hostile cases, a ten-category attack matrix, minimum-authority checks,
  profile coverage, secret-surface checks, and repeated overhead measurement.
- Utility evidence: W01-W05 passed across Controlled, Sealed, and Basic. The
  fully hostile path still completed one permitted harmless read before the
  secret-reveal request was denied. The baseline reference applied a protected
  read plus external send; Tkach allowed only the read.
- Security evidence: defined false allows were zero; protected public export,
  scope widening, secret reveal, replay, malformed output, timeout/failure/
  cancellation, and premature egress were contained. DATA remained useful
  data in the authority-forgery and DATA-to-CONTROL cases. Removing write or
  secret authority produced zero effects while approved read remained useful.
- Integration: `QUICKSTART.md` and the compiling/running
  `examples/quickstart.rs` document the actual Basic path. Controlled and
  Sealed paths remain explicit typed test fixtures, not an SDK or DSL.
- Self-review hardening: the oracle was strengthened to scan output, errors,
  traces, and broker diagnostics for the fake secret; the attack matrix was
  made explicit about useful authority-forgery/data-control cases; lint and
  compile issues were fixed before the final validation rerun. No production
  security code changed in this phase.
- Validation: debug/release workspace tests, fmt, clippy, audit, deny, fuzz
  compile, Product Proof tests, and Quickstart execution passed. The measured
  performance result is host-specific and has no threshold. Live OpenAI was
  skipped because opt-in credentials were absent.
- Security review: Standard Codex Security scan
  `b8d05e0d-45ea-4d7d-8d86-74b3162f506d` completed with zero reportable
  findings and partial coverage. The automated diff runner again rejected the
  valid non-bare repository as lacking a resolvable HEAD; a full manual
  source-backed range review was completed and the limitation is retained.
- Commits: `629d6a2`, `b0e343b`, `d56b55a`, `deb28b8`, followed by the final
  Product Proof documentation/checkpoint commit. Local tag: `product-proof-v0.1`.
- Status: Product Proof Checkpoint PASS. Worktree clean; no push. Product
  limitations remain the fake offline environment, no transaction/production
  executor semantics, no semantic prompt-injection solution, partial scan
   coverage, and unavailable Windows libFuzzer execution.

## Phase C — Canonical terminology migration and integration proof

- The public tracked surface uses canonical `Ruslo` and `Klyuchnik` names with
  no compatibility aliases or wrappers; module/file paths and capability
  evidence names were migrated mechanically without changing enforcement order.
- Commit `13ae3b5` records the rename-only security regression gate. Commit
  `655a3b4` records the realistic workflow, compromised-provider, continuation,
  explicit Public-flow, and performance-breakdown tests.
- The coding-agent proof performs two permitted reads, analyzes hostile DATA,
  performs one scoped write, and returns a result. Internal release succeeds;
  the same protected-derived output to public egress is denied.
- A fully compromised provider obtains one useful permitted read, then cannot
  replay, widen capability, write/send without authorization, reveal a
  Klyuchnik secret, or turn DATA into CONTROL. A deny is terminal for one run;
  only a new explicitly bounded run may continue.
- `PRODUCT_PROOF_REPORT.md` records the 14-test run and host-specific
  Gateway/Krosna/Ruslo/Zaslon/Niti-Metka/Klyuchnik/parse observations.
  `INTEGRATION_PROOF_CHECKPOINT.md` is the Phase C acceptance record.

## Autonomous Production Hardening — Part A

- Scope: close the offline fake-executor gap without adding OpenAI, Anthropic,
  MCP, SDK, UI, cloud, or production gateway transport integrations.
- Architecture: `RealEffectExecutor` is the existing Propusk-only
  `ProtectedExecutor` boundary with three fixed bindings: bounded read of
  `workspace/input.txt`, create-only write of `workspace/output.txt`, and a
  fixed HTTP request to an explicitly configured loopback endpoint. The model
  cannot choose an OS path, endpoint, HTTP path, or payload.
- Public flow: `Krosna::authorize_tagged_public_send` is a narrow trusted-
  ingress bridge requiring `Public` tagged data, an explicit Ruslo Export
  allow, and the ordinary action policy. The normal untrusted Gateway path
  still denies public network proposals.
- Failure contract: pre-effect validation/connect failures return
  `FailedBeforeEffect`; failures after bytes may have been written/sent return
  `OutcomeUnknown`; only verified create/2xx results produce `Committed`
  payload-free receipts with bounded executor sequence IDs.
- Filesystem contract: canonical root/parent/target checks reject links,
  reparse points, absolute/drive/backslash/dot/parent paths, missing parents,
  outside-root targets, sibling lookalikes, and overwrite attempts. The
  create-only write intentionally makes no rollback claim.
- TOCTOU: safe portable Rust checks and post-use rechecks reduce path races,
  but no universal handle-relative/no-follow transaction exists in the
  standard library. This residual is documented in
  `REAL_EFFECT_CONTRACT.md`; deployments requiring hostile concurrent mutation
  must use an OS-specific reviewed adapter or deny this profile.
- Verification: `real_effects.rs` proves actual isolated filesystem writes,
  exact loopback request delivery, Gateway dispatch, deny-before-connect,
  symlink/parent/path mutation cases, non-2xx failure, and timeout unknown
  outcomes. The suite contains 9 tests.
- Implementation commits: `ef0f185` classifies effect outcomes;
  `e72619e` adds the real local boundary and first adversarial suite. The
  follow-up Gateway integration tests and contract documentation are pending
  the final checkpoint commit/tag.
