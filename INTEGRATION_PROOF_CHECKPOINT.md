# Strong Core Integration Proof Checkpoint

Status: PENDING FINAL MATRIX — the evidence below is the Phase C acceptance
contract; it becomes PASS only after the complete validation, security review,
clean worktree check, and local tag are recorded.

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
