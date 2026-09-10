# Development Record

This is a concise continuity log, not an active mandate or a diary. Current
behavior is in `CURRENT_BASELINE.md`; validation evidence is in `EVIDENCE.md`;
permanent rules are in `../Tkach Security — MASTER_MANDATE.md`.

## Milestones

- `20da435`, `f13ac50`, `eb1aea7`: removed vocabulary-only API surface and
  completed the architecture/product-contract pruning review.
- `b0e343b`, `deb28b8`, `7ec26d5`: added the offline Product Proof harness,
  useful/hostile workload pairs, and its checkpoint/tag.
- `13ae3b5`, `5f2aeb1`: completed the canonical `Ruslo`/`Klyuchnik`
  terminology migration and integration-proof checkpoint.
- `e72619e` through `0b2887a`: added the narrow real filesystem/loopback
  effect boundary, fault semantics, package evidence, and its checkpoint/tag.
- `a7417aa` through `41e9ca0`: added bounded authenticated runtime admission,
  loopback framing, replay/cancellation/shutdown semantics, safe receipts,
  runtime threat/ownership evidence, and the local
  `production-runtime-v0.1` tag.
- `446dc6f`: consolidated the authoritative current baseline and removed
  completed-phase instructions from the permanent constitution.
- `756d695`: stored the trusted runtime authentication proof in
  `zeroize::Zeroizing<Vec<u8>>`; redaction, constant-time comparison, and
  authentication-before-Gateway behavior remained unchanged.
- `823d0f0`: stored the OpenAI adapter's trusted configuration credential in
  `zeroize::Zeroizing<String>`; HTTP-client/header and caller buffers remain
  explicitly outside the ownership claim.
- `7389023`: made CI mirror the local release matrix for metadata, release
  tests, docs/rustdoc, packaging, and Quickstart.
- `f1c052c`: established the v0.1 public Rust API boundary and consumer-side
  Gateway API smoke test without changing Core.
- current Productization cycle: added the bounded `tkach` onboarding CLI with
  strict `init`/`check`/`run --demo` commands, no-overwrite behavior, and
  symlink/reparse-point rejection.
- current checkpoint cycle: reran the local Strong Core matrix and recorded
  the bounded release decision and residual claims in `EVIDENCE.md`.

## Security review rules applied

Every boundary change was reviewed for fail-open behavior, `UNKNOWN` becoming
allow, authority laundering, scope widening, Niti/Metka loss, Zaslon
representation bypass, Ruslo direction confusion, Klyuchnik/Sled leakage,
raw-request execution, parser ambiguity, and resource exhaustion.

The current repository retains the explicit deployment residuals: caller
authentication trust, TLS/IPC, OS/process isolation, durable replay, universal
filesystem race prevention, forceful interruption, host compromise, and
semantic prompt-injection detection. These are not silently upgraded into
guarantees by local tests.

## Working agreement

Use the engineering loop: design, implement, test, challenge, fix, re-test,
review the diff, update `CURRENT_BASELINE.md`/`EVIDENCE.md`, and create one
coherent local commit. Do not push without explicit owner instruction.
