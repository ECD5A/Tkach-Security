# Tkach Security Production Runtime Checkpoint

Date: 2026-09-11

Baseline: 0b2887a93270dd3d5e93e31f3a41dc213cbde0bc
(production-boundary-v0.1)

## Decision

PASS on authoritative local evidence for Production Runtime Hardening v0.1.
The implementation, documented residuals, local security tests, full debug and
release matrix, package checks, and clean-worktree review are complete. The
annotated production-runtime-v0.1 tag is created only after this checkpoint and
report are committed.

## Required local gates

- R0/R1 threat and ownership models are implemented, reviewed, and updated.
- R2-R4 filesystem no-follow and TOCTOU controls are implemented with an honest
  portable residual; Unix and Windows-specific behavior is separated without
  unsafe Rust.
- R5/R6/R12/R13 distinguish FAILED_BEFORE_EFFECT from OUTCOME_UNKNOWN; unknown
  outcomes are terminal and have no automatic retry.
- R7-R10 provide fixed loopback effects and a bounded authenticated local frame
  service; authentication is not authorization.
- R11/R14-R16/R20/R22/R27 provide request/lifecycle identity, shutdown,
  cancellation, concurrency, replay, response, and resource bounds.
- R17 zeroizes private broker-held SecretValue bytes on drop. No host-memory,
  core-dump, or caller-copy zeroization claim is made.
- R18/R19/R21 document BASIC/CONTROLLED/SEALED ownership, out-of-band bypass,
  safe receipts, and safe observability.
- R23-R26/R31/R34 hostile filesystem, network, fault, panic, runtime E2E, and
  red-team checks are present.
- R28-R30/R33 packaging, property/oracle, mutation, and documentation checks
  are complete.

## Authoritative evidence

- Debug workspace tests: 113 core, 9 composition, 9 independent oracle,
  49 Gateway unit, 25 Gateway boundary, 14 product proof, 13 real effects,
  33 provider, and 1 opt-in live guard; all passed.
- Release workspace tests: the same suites passed.
- Formatting, workspace clippy with warnings denied, rustdoc with warnings
  denied, locked metadata, offline audit, and cargo-deny passed.
- Fuzz workspace binaries compiled with locked offline dependencies.
- All three workspace crates packaged offline; quickstart emitted its bounded
  response message.
- Targeted runtime mutation: 110 mutants, 85 caught, 24 platform/build
  unviable, one diagnostic-only Visitor::expecting survivor. No security-path
  mutant survived. Existing property and independent-oracle suites passed.
- Full Gateway mutation was run as exploratory evidence before final coverage
  tightening: 391 caught, 103 unviable, and 86 manually reviewed misses,
  consisting of debug/fake-harness/platform branches. The final targeted
  runtime run is the authoritative mutation result for this phase's changed
  runtime path.

## External tooling limitation

Codex Security scans: INCONCLUSIVE / unavailable due to stalled external tooling; not used as security evidence.

The pre-existing handles b8e5aaa2-ae7b-4f05-bf06-8b348bdc59d9
(threat_model) and 7d49ba8c-611f-4e4b-8bfc-fffc77df95f4 (preflight) remain
running without terminal artifacts. No new external scan was started and no
existing scan was canceled. Their reported interim zero-candidate state is not
treated as PASS.

## Remaining boundary

Portable standard Rust still cannot prove a universal handle-relative,
parent-component no-follow filesystem transaction on every platform. Windows
stable metadata on this MSRV is an observation rather than a unique file-ID
proof. The built-in runtime listener is loopback-only, sequential, in-memory,
and not TLS, process isolation, durable replay, or a public internet gateway.
Blocking synchronous provider and OS calls are not forcefully interruptible.
Same-privilege out-of-band effects and fully compromised hosts remain outside
the claim.

## Finalization

The final report is PRODUCTION_RUNTIME_REPORT.md. After its commit, the local
annotated tag production-runtime-v0.1 must point at the final HEAD, and the
worktree must remain clean. No push is authorized.
