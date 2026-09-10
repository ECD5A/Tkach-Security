# Roadmap

- DONE — Gateway Hardening 1.5 (2026-09-10; lifecycle/effect ordering,
  aggregate budget hardening, and 313-mutant triage complete).
- CURRENT — Real Provider Phase v0.1: OpenAI Responses API boundary; P0 threat
  model and P1-P8 non-streaming adapter are implemented, with final validation
  and provider checkpoint still in progress.

The permanent mandate is the source of truth. States below describe this
repository, not future product marketing.

- DONE — Mandate 0: foundation and security baseline.
- DONE — Mandate 1: strong typed security domain model.
- DONE — Mandate 2: Krosna deterministic kernel.
- DONE — Mandate 3: Zaslon hard-deny enforcement.
- DONE — Mandate 4: Gnezdo data/control containment.
- DONE — Mandate 5: Propusk scoped authorization.
- DONE — Mandate 6: Niti and Metka conservative lineage.
- DONE — Mandate 7: Diode directional flow enforcement.
- DONE — Mandate 8: Pechat opaque secret broker.
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
- DEFERRED — Anthropic, MCP, SDKs, UI, cloud, and production gateway
  transport.
