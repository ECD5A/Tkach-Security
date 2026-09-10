# Product Contract Checkpoint

Status: pending final validation on the architecture-pruning head.

This is the A20 evidence checklist for the Architecture Pruning & Product
Contract Review. A check is considered passing only when the implementation,
tests, and documentation agree.

| # | Check | Evidence / acceptance condition |
| ---: | --- | --- |
| 1 | Product contract is clear | `PRODUCT_CONTRACT.md` states the problem, guarantees, assumptions, and non-guarantees. |
| 2 | Guarantees are conditional and honest | Deployment assumptions and out-of-band bypass limits are explicit. |
| 3 | Non-guarantees are explicit | Prompt injection, semantic intent, compromised host, production transactions, and deferred integrations are excluded. |
| 4 | Every primitive has a role | `PRIMITIVE_REVIEW.md` and `SECURITY_VALUE_MAP.md` map each named primitive to a threat and enforcement point. |
| 5 | Unjustified wrappers are removed | `DataLane`, empty `Pechat`, and `ScriptedProvider` are absent from the public source surface. |
| 6 | Public API is reduced or justified | `PRUNING_METRICS.md` records the public-surface reduction and retained boundary rationale. |
| 7 | Security logic is not duplicated without a boundary | Krosna, Diode, Gateway, and provider checks are documented as separate trust boundaries. |
| 8 | Integration model is clear | `INTEGRATION_MODEL.md` specifies Gateway ingress, provider DATA, core gates, executor, and release. |
| 9 | Deployment profiles are clear | Basic, Controlled, and Sealed profiles are defined with assumptions and unavailable guarantees. |
| 10 | Secure defaults are visible | Default deny, bounded inputs, no provider persistence/tools, no redirects, and no live network tests by default are documented. |
| 11 | Hostile-model guarantees remain | Simplification red-team matrix passes and no removed wrapper supplied authority. |
| 12 | OpenAI boundary remains green | Existing provider test, parser, transport, replay, and fixture matrix passes. |
| 13 | Strong Core remains green | Existing Strong Core tests and invariant documentation remain unchanged in security meaning. |
| 14 | Gateway remains green | Existing Gateway lifecycle, egress, action, replay, and provider-failure matrix passes. |
| 15 | Simplification red-team passes | `SIMPLIFICATION_RED_TEAM.md` records the attacks, expected denials, and evidence. |
| 16 | Changed security code has mutation evidence | Core pruning mutation run has no unexplained security-relevant survivor; provider/Gateway baselines remain recorded. |
| 17 | Documentation matches source | Final review updates roadmap, architecture, security model, terminology, contract, and metrics. |
| 18 | Complexity did not increase without reason | `ARCHITECTURE_COST_REVIEW.md` and dependency review show no new runtime dependency, DSL, or policy engine. |
| 19 | Changes are committed locally | Final commit list is recorded in the final report; worktree is clean. |
| 20 | No remote publication occurred | No `git push` is part of this phase. |

The status changes to PASS only after the complete final command matrix, the
pruning-range diff review, and the final clean-worktree check succeed.
