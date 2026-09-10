# Product Proof Checkpoint

Status: PASS — Product Proof B0-B22 completed locally on 2026-09-10.

| # | Requirement | Evidence |
| ---: | --- | --- |
| 1 | Hostile provider cannot create unauthorized protected effect | Product Proof attack matrix; false allows must remain zero |
| 2 | Legitimate permitted work continues | W01-W05 typed workload rows |
| 3 | Legitimate/adversarial pairs exist | `SECURITY_UTILITY_BENCHMARK.md` and harness |
| 4 | False allows are zero | Structured effect/external-send assertions |
| 5 | False denies are measured | `Observation`/`ReportRow` and workload assertions |
| 6 | READ and EXPORT are distinct | Internal summary success/public export denial |
| 7 | Klyuchnik secret remains non-model-visible | Output/error/trace/broker debug scan |
| 8 | Minimum authority is demonstrated | Read-only/write-removed/secret-removed tests |
| 9 | Basic/Controlled/Sealed are distinguished | Profile-tagged report and Quickstart |
| 10 | Integration effort is measured | Quickstart/example line and concept counts |
| 11 | Quickstart matches actual API | Compiled and executed `examples/quickstart.rs` |
| 12 | Tkach overhead is measured | Repeated benchmark-level performance probe |
| 13 | Attack containment matrix exists | Ten typed attack/failure categories |
| 14 | Security does not depend on detector | Gnezdo/authorization/flow tests with hostile DATA |
| 15 | Live OpenAI is optional | Env/key absent; no live request made |
| 16 | Utility did not weaken security | No production security code changed in proof phase |
| 17 | Defects have regression coverage | Harness oracle/lint fixes and existing regressions |
| 18 | Baseline suites remain green | Debug/release workspace matrix, clippy, audit, deny, and fuzz compile passed |
| 19 | Changes committed locally | Commit list in final report |
| 20 | No remote publication | No `git push` |

## Final evidence

- Product Proof B22 baseline harness: 10 tests passed with `--nocapture`; W01-W05 passed,
  all defined hostile variants contained unauthorized effects, and the attack
  matrix recorded zero false allows.
- The Phase C extension reran the harness with 14 tests, adding the realistic
  multi-step, fully compromised, fresh-run continuation, and performance
  breakdown evidence. The current acceptance record is
  `INTEGRATION_PROOF_CHECKPOINT.md`.
- Workspace validation: debug and release all-target tests passed (216 tests
  in the debug aggregate), format and clippy with warnings denied passed,
  `cargo audit --no-fetch` reported no advisories, `cargo deny check` passed
  advisories/bans/licenses/sources, and the fuzz crate compiled offline.
- Quickstart: `cargo run -p tkach-gateway --example quickstart --locked`
  compiled and executed successfully.
- Standard Codex Security scan `b8d05e0d-45ea-4d7d-8d86-74b3162f506d`
  completed with zero reportable findings and partial coverage. The partial
  status records unavailable delegated workers and excluded generated target
  trees.
- The automated diff runner repeatedly rejected the valid non-bare worktree as
  lacking a resolvable HEAD. A source-backed review of the complete range
  `2e622ffc..deb28b8` therefore supplied the diff evidence; this is recorded as
  a tooling limitation, not an automated diff-scan PASS.
- No production security code or primitive semantics changed in Product Proof;
  the harness and Quickstart are test/example surfaces only. No live OpenAI
  request was made because the opt-in environment variables were absent.
- Worktree was clean after validation. No remote publication was performed.
