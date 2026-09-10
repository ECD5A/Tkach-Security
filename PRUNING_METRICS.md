# Architecture Pruning Metrics

This record compares the frozen `openai-provider-v0.1` baseline at
`59142d8360ca5487cb15a56b19c75da6213124fa` with the post-pruning tree. The
measurements are repository measurements, not estimates of future SDK or
deployment code.

## Before / after

| Measure | Before | After | Interpretation |
| --- | ---: | ---: | --- |
| Production Rust crates | 3 | 3 | No new runtime component was introduced. |
| Production Rust files | 21 | 21 | Pruning was structural, not file churn. |
| Production Rust LOC | 12,966 | 12,904 | 62 physical lines removed. |
| Public declaration/field lines (approx.) | 372 | 364 | 8 public surface lines removed. |
| Unique direct normal dependency names | 7 | 7 | No dependency was added; one duplicate dev declaration was removed. |
| Workspace tests | 208 | 206 | Two tests for removed vocabulary-only wrappers disappeared; security coverage remains. |
| Production network-code crates | 1 | 1 | The bounded OpenAI adapter remains the only network boundary. |

The public-line count is a source inspection metric: it counts public
declarations and public fields, not every exported re-export or generated
item. The dependency count is name-based and excludes dev-only and fuzz-only
edges; the complete dependency rationale is in `DEPENDENCY_REVIEW.md`.

## Security-preserving interpretation

- No Krosna, Propusk, Ruslo, Zaslon, Klyuchnik broker, Gnezdo, Niti, Metka, or
  Sled enforcement mechanism was removed.
- `DataLane` was a zero-sized naming marker; Gnezdo already enforces the data
  lane through its validated context. `Klyuchnik` was an empty facade; the real
  boundary is `SecretBroker` plus `SecretHandle`. `ScriptedProvider` was an
  alias; `DeterministicProvider` remains the test provider.
- The removed names have no remaining source callers. The post-pruning core
  mutation run tested 55 mutants: 46 caught and 9 unviable, with no unexplained
  security-relevant survivor.
- The 206-test matrix, clippy, release tests, dependency checks, fuzz-target
  compile check, and diff review are the required final evidence for the
  checkpoint. Results are recorded in `DEVELOPMENT.md` and
  `PRODUCT_CONTRACT_CHECKPOINT.md`.
