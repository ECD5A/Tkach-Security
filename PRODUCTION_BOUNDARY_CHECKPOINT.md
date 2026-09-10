# Strong Core Checkpoint — production boundary candidate

Date: 2026-09-10  
Baseline: `5f2aeb133607207cabb68e82bbdf1f62dd4e5219`
(`integration-proof-v0.1`)  
Implementation hardening: `6d66259`

## Decision

The local Strong Core implementation and repository verification matrix pass.
The release tag is intentionally withheld: two pre-existing headless Standard
Codex Security scans are still `running` and have no terminal report. This
record therefore does not claim a final Strong Core PASS until those scans are
terminally complete.

## Architecture and authority

- Krosna remains the deterministic authorization kernel; provider code does
  not define policy semantics.
- Real effects remain behind `Propusk` and `ProtectedExecutor`.
- `RealEffectExecutor` exposes only fixed sandbox read/create-only write and
  configured non-zero loopback HTTP bindings.
- The model cannot select an OS path, endpoint, HTTP path, or effect payload.
- The public network bridge requires trusted `Public` tagged ingress, explicit
  Ruslo `Export`, and ordinary Krosna authorization.
- Klyuchnik remains handle-only at the model boundary; receipts, errors,
  Debug, and traces are payload-free.

## Real effect evidence

| Boundary | Evidence | Result |
| --- | --- | --- |
| Filesystem read | actual isolated `workspace/input.txt`, bounded UTF-8 and Confidential provenance | PASS |
| Filesystem write | actual create-only `workspace/output.txt`, exact bytes, sync/readback/final check | PASS |
| Network | actual receiver saw one exact fixed HTTP request on configured loopback | PASS |
| Denials | hostile path/resource/destination/public-flow variants made zero receiver connections | PASS |
| Failure | non-2xx, oversized response, timeout and post-connect failures are `OutcomeUnknown` | PASS |
| Receipts | bounded sequence, typed operation/resource/destination/outcome, no payload | PASS |

## Filesystem and TOCTOU

Root, parent, and target use metadata and canonical containment checks; links,
Windows reparse points, traversal/normalization syntax, wrong siblings,
missing parents, outside-root targets, and overwrites are denied. The write is
create-only and deliberately does not perform uncertain-path cleanup.

Portable standard Rust still cannot provide a universal handle-relative,
no-follow transaction. Metadata/open/recheck behavior reduces this race and
reports post-open uncertainty, but same-process hostile concurrent mutation is
not claimed impossible. Such deployments must use a separately reviewed
OS-specific adapter or deny this profile.

## Verification

- Debug/full matrix: 112 core, 9 composition, 9 independent oracle, 27
  Gateway unit, 25 boundary, 14 product proof, 13 real effects, 33 provider,
  and 1 live guard; all passed.
- Release/full matrix: same suites passed.
- `cargo fmt --all -- --check`, workspace clippy with warnings denied,
  `cargo doc --workspace --all-features --no-deps`, and locked metadata passed.
- Offline fuzz workspace check passed; generated `fuzz/target` was removed and
  remains ignored.
- `cargo package --workspace --allow-dirty --no-verify --offline` packaged all
  three crates.
- `cargo audit --no-fetch` and escalated `cargo deny check` passed; only
  duplicate dependency warnings remain.
- Quickstart printed `Basic Gateway released one bounded response`.
- Protected-path mutation subset: 88 tested, 82 caught, 6 unviable, 0 missed.
  A separate 94-mutant run's only miss was the non-Windows constant branch,
  which is not compiled on this Windows host; its Windows implementation has
  direct metadata coverage.

## Scan state and remaining gates

The following pre-existing scans remain active and are not claimed complete:

- `b8e5aaa2-ae7b-4f05-bf06-8b348bdc59d9` — Standard scan at `threat_model`,
  zero candidates so far, no report artifacts.
- `7d49ba8c-611f-4e4b-8bfc-fffc77df95f4` — Standard scan at `preflight`, zero
  candidates so far, no report artifacts.

The first identifier above is recorded as returned by the security workbench;
the second is the separate later scan. Final tag/PASS requires terminal
status and a final review of their canonical artifacts. No push is authorized.

## Current conclusion

Implementation quality is sufficient for the local production-boundary
candidate, with TOCTOU and generic-transport limitations explicitly retained.
Final Strong Core completion remains pending the two active security scans;
after they terminate, rerun the clean-status check and tag only if no new
reportable security defect remains.
