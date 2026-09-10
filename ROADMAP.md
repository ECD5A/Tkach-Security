# Roadmap

- DONE — Gateway Hardening 1.5 (2026-09-10; lifecycle/effect ordering,
  aggregate budget hardening, and 313-mutant triage complete).
- DONE — Real Provider Phase v0.1: OpenAI Responses API boundary; P0 threat
  model, P1-P8 non-streaming adapter, adversarial hardening, and provider
  checkpoint are complete at tag `openai-provider-v0.1`.

The permanent mandate is the source of truth. States below describe this
repository, not future product marketing.

- IN PROGRESS - Production Runtime Hardening v0.1: runtime threat/ownership
  model, platform-aware no-follow opens, zeroized Klyuchnik storage, bounded
  authenticated loopback framing, lifecycle replay, cancellation, shutdown,
  safe receipts, and hostile runtime/fault/property/mutation validation.

- DONE — Mandate 0: foundation and security baseline.
- DONE — Mandate 1: strong typed security domain model.
- DONE — Mandate 2: Krosna deterministic kernel.
- DONE — Mandate 3: Zaslon hard-deny enforcement.
- DONE — Mandate 4: Gnezdo data/control containment.
- DONE — Mandate 5: Propusk scoped authorization.
- DONE — Mandate 6: Niti and Metka conservative lineage.
- DONE — Mandate 7: Ruslo directional flow enforcement.
- DONE — Mandate 8: Klyuchnik opaque secret broker.
- DONE — Mandate 9: Sled and enforcement testbed.
- DONE — Mandate 10: composition testing.
- DONE — Mandate 11: core red team and adversarial parser/authority review.
- DONE — Mandate 12: production-oriented core hardening.
- DONE — Strong Core Hardening Round 2 (2026-09-10; mutation, oracle, and
  cross-primitive review completed).
- DONE — Strong Core Checkpoint re-run (2026-09-10; 60 conditions reviewed).
- DONE — Strong Core Final Hardening Round 3 and freeze validation; gateway work
  remains intentionally out of scope.
- DONE — Gateway Phase 1 G0 threat model (provider-independent boundary).
- DONE — Gateway Phase 1 G1-G10 bounded in-process gateway, hostile fake
  providers, protected tool boundary, canonical scenario, and red-team tests.
- DONE — Gateway Phase 1 checkpoint (2026-09-10; HEAD `c77e6e1`).
- DONE — Real Provider P0 threat model (commit `32ab2ac`).
- DONE — Real Provider P1-P8 non-streaming OpenAI adapter (commit `a8d67dd`):
  bounded config/HTTPS transport, strict wire parser, fixed proposal mapping,
  replay markers, Gateway integration, fixtures, fuzz target, and opt-in live
  smoke test.
- DONE — Real Provider adversarial/mutation hardening: 33 all-feature tests,
  bounded transport checks, and 201-mutant review; streaming remains disabled
  by design for the synchronous Gateway contract.
- DONE — Architecture Pruning & Product Contract Review A0-A20: product
  contract, primitive review, safe API pruning, integration profiles,
  dependency/complexity review, hostile simplification review, and checkpoint
  evidence are complete at the final local head.
- DONE — Product Proof B0-B22 (2026-09-10): executable offline benchmark,
  paired legitimate/hostile workloads, attack matrix, Basic/Controlled/Sealed
  evidence, Quickstart, performance observation, security review, checkpoint,
  and local tag `product-proof-v0.1`.
- DONE — Phase C Canonical Terminology Migration + Integration Proof
  (2026-09-10): canonical naming migration completed without aliases, realistic
  multi-step workflows, compromised-provider utility proof, misuse/continuation
  checks, canonical value map, performance breakdown, and integration
  checkpoint at local tag `integration-proof-v0.1`.
- DONE — Autonomous Production Hardening Part A: narrow real filesystem and
  loopback effect boundary, exact create-only semantics, public-flow binding,
  failure/timeout classification, receipt hardening, and isolated adversarial
  tests. Checkpoint/tag follows only after the full final matrix.
- DEFERRED — Anthropic, MCP, SDKs, UI, cloud, and production gateway transport.
