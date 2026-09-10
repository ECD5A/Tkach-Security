# Product Proof Checkpoint

Status: pending final full validation and security review.

| # | Requirement | Evidence |
| ---: | --- | --- |
| 1 | Hostile provider cannot create unauthorized protected effect | Product Proof attack matrix; false allows must remain zero |
| 2 | Legitimate permitted work continues | W01-W05 typed workload rows |
| 3 | Legitimate/adversarial pairs exist | `SECURITY_UTILITY_BENCHMARK.md` and harness |
| 4 | False allows are zero | Structured effect/external-send assertions |
| 5 | False denies are measured | `Observation`/`ReportRow` and workload assertions |
| 6 | READ and EXPORT are distinct | Internal summary success/public export denial |
| 7 | Pechat secret remains non-model-visible | Output/error/trace/broker debug scan |
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
| 18 | Baseline suites remain green | Final matrix required below |
| 19 | Changes committed locally | Commit list in final report |
| 20 | No remote publication | No `git push` |

The checkpoint may become PASS only after the full workspace matrix, audit,
deny, fuzz compile, diff review, and security review succeed.
