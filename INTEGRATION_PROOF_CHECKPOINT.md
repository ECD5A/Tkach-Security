# Strong Core Integration Proof Checkpoint

Historical Phase C evidence only; this checkpoint is not an active mandate.

Status: PASS — Phase C acceptance completed locally on 2026-09-10 after the
complete validation matrix, security self-review, clean worktree check, and
local tag.

Baseline: `product-proof-v0.1` at `7ec26d5`.

| # | Phase C condition | Evidence / acceptance rule |
| ---: | --- | --- |
| 1 | Mandate and architecture were reread | `Tkach Security — MASTER_MANDATE.md` and current architecture/security docs were read before implementation |
| 2 | Canonical terminology is complete | Public modules, files, types, methods, tests, capabilities, and docs use `Ruslo` and `Klyuchnik` |
| 3 | No compatibility aliases remain | No dual names, wrappers, or migration shims are tracked |
| 4 | Old terminology search is clean | `git grep -i` for the retired terms returns no current tracked surface |
| 5 | Rename semantics are preserved | Rename diff is mechanical; Krosna precedence, default-deny, flow gates, Propusk, Gnezdo, Niti/Metka, secrets, lifecycle, and effect order are unchanged |
| 6 | Rename regression gate passes | Workspace check, core/gateway boundary suites, debug/release tests, and renamed unit tests pass |
| 7 | Real coding-agent workflow passes | User task + hostile issue DATA: two reads, scoped write, useful result, zero public send |
| 8 | Internal assistant workflow passes | Protected read and internal summary succeed |
| 9 | Public boundary remains fail closed | The same protected-derived summary to public egress is denied with zero external sends |
| 10 | Klyuchnik workflow passes | Authorized opaque-handle use succeeds; raw reveal/export fails; result/error/trace/debug are clean |
| 11 | Fully compromised provider is contained | Useful permitted read may complete; replay/escalation/write/send/reveal/DATA-control attempts produce zero unauthorized effects |
| 12 | Denial continuation semantics are explicit | Denial is terminal for one run; only a new bounded lifecycle may continue, with no staged-state reuse |
| 13 | False-deny pressure is reviewed | Approved read, scoped write, internal flow, explicit core Public flow, and Klyuchnik action are tested or explained |
| 14 | Minimum authority is demonstrated | Removing write/secret authority denies only those effects while approved read remains useful |
| 15 | Deployment profiles are distinguished | Basic, Controlled, and Sealed have executable evidence and documented limits |
| 16 | Misuse-resistant API behavior is checked | Missing capability, wrong scope, missing/unknown classification or destination, unknown tool, raw secret, invalid handle, replay, and untrusted trusted-constructor attempts fail closed or are type-inaccessible |
| 17 | Quickstart is real | Quickstart example compiles and runs against the current renamed API |
| 18 | Performance breakdown exists | Repeated host-specific observations cover Gateway, Krosna, Ruslo, Zaslon, Niti/Metka, Klyuchnik, parsing, and total; no SLA claim |
| 19 | Product claim is bounded | The compromised-model/deterministic-boundary claim is stated with its routing condition and limitations |
| 20 | Canonical value map is complete | `SECURITY_VALUE_MAP.md` maps all nine primitives to threat, invariant, workload, removal consequence, and classification |
| 21 | Documentation is problem-first | README, Quickstart, contract, integration model, threat/security docs, benchmark, report, roadmap, and development log use canonical terms |
| 22 | Migration red-team was attempted | Search, API compilation, rename regression tests, attack matrix, and manual diff review cover naming seams |
| 23 | Debug matrix passes | Workspace all-target debug tests pass with all features and lockfile |
| 24 | Release matrix passes | Workspace all-target release tests pass with all features and lockfile |
| 25 | Static and supply-chain gates pass | Format, clippy `-D warnings`, audit, deny, fuzz compile, and relevant smoke checks pass |
| 26 | Security review is honest | Standard scan, available diff review, manual source-backed review, and tooling limitations are recorded without overstating coverage |
| 27 | Delivery state is controlled | Meaningful local commits exist, checkpoint is PASS, tag `integration-proof-v0.1` points to new HEAD, worktree is clean, and no push was made |

## Required security outcome

The checkpoint cannot pass if any defined false allow occurs, a raw broker
secret appears in a result/error/trace/debug surface, a legitimate representative
workflow is silently denied without an architectural explanation, or an
unexplained security-relevant mutation survives.

## Final evidence

- Debug and release workspace matrices passed: 111 core unit tests, 9
  composition tests, 9 independent oracle tests, 19 Gateway unit tests, 25
  Gateway boundary tests, 14 Product Proof tests, 33 provider tests, and one
  guarded live-test case.
- `cargo fmt --all -- --check`, workspace clippy with `-D warnings`,
  `cargo audit --no-fetch`, `cargo deny check`, fuzz-bin offline compilation,
  and the Quickstart run passed. Audit/deny reported only the known duplicate
  `syn` and `windows-sys` warnings; no advisories were reported.
- The old terminology search is empty across the tracked and worktree source
  surface. `fuzz/target/` and literal `%TEMP%/` are absent; both generated
  paths remain ignored.
- Manual review of exact range `7ec26d5..HEAD` found mechanical canonical
  renames plus proof/documentation additions. No Krosna precedence, default
  deny, flow, Propusk, Gnezdo, Niti/Metka, Klyuchnik, lifecycle, or effect
  ordering change was found. Existing property/oracle and mutation evidence
  remains applicable because production security logic was not redesigned.
- Completed prior Standard scan `b8d05e0d-45ea-4d7d-8d86-74b3162f506d`
  reported zero reportable findings with partial coverage. The current
  headless scan was started for this phase but remained in `threat_model` with
  zero closed surfaces; its non-completion is not presented as a scan PASS.
  The automated diff runner has the documented non-bare-HEAD limitation, so
  the current range is covered by the source-backed manual review above.
- No live OpenAI run was made because both opt-in environment variables were
  absent. No remote publication was performed.
