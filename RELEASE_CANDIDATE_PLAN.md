# Strong Release Candidate v0.1 — Active Plan

This is the active development plan after `production-runtime-v0.1`. It is
subordinate to the current owner mandate, source/tests, `CURRENT_BASELINE.md`,
and the permanent constitution.

## Phase 0 — authoritative state consolidation

Status: complete in the documentation-consolidation commit.

- finished mandate instructions and temporary bans were removed from the
  permanent constitution;
- historical checkpoints/reports are labeled as evidence only;
- current architecture, product, security, roadmap, and integration docs are
  reconciled with the source and tests;
- one short current baseline is established;
- the complete local validation matrix is green for this documentation state.

No runtime or core functions are added in this phase.

## Phase 1 — boundary/product risk review

After the Phase 0 commit, review the actual remaining risks in this order:

1. protected-effect bypasses and deployment-boundary assumptions;
2. authentication/IPC, process isolation, replay durability, and filesystem
   residuals;
3. integration friction and misuse-resistant typed entry points;
4. useful legitimate workloads under a hostile model.

Core primitives remain frozen unless a concrete reproducible defect is found.
Any selected hardening phase must add adversarial regression coverage and
re-run the full local gates before documentation and commit.

## Integration decision rule

An external protocol adapter is considered only after the preceding risk review
shows that it improves a real product boundary without duplicating authority.
If MCP is selected, it must be a thin, provider-independent adapter over the
existing Gateway/Krosna/Propusk/Ruslo/Zaslon/Klyuchnik/Sled authority path. It
must not become a second policy engine or be added for feature count.

The current baseline contains no MCP implementation. This is a current scope
fact, not a permanent constitutional ban.

## Release-candidate exit bar

Stop only when the repository has one authoritative architecture, minimal
non-contradictory active documentation, a stable core, real protected effects
behind the boundary, model-independent authorization, useful and hostile-model
workloads, measured false allows/denies, misuse-resistant integration, offline
reproducible validation, explicit deployment assumptions, and no unexplained
security-relevant finding.

At that point create the local annotated tag
`strong-release-candidate-v0.1`, write the final report with PROVEN/PARTIAL/
UNPROVEN claims, verify HEAD and a clean worktree, and stop. Do not push.
