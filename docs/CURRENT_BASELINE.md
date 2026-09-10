# Tkach Security — Current Baseline

Status: authoritative current-state summary. The production-runtime baseline
is tagged `production-runtime-v0.1` at `41e9ca0a374cfb95ac1a1ed3a5b22ce6445d9283`;
the current source also includes reviewed runtime-proof hardening `756d695`
and OpenAI credential ownership hardening `823d0f0`.

This file describes what is implemented now. It is not a replacement for the
permanent constitution, source code, or executable tests.

## Authority and reading order

For a conflict, use this order:

1. the current owner mandate;
2. current source code and executable tests;
3. this file;
4. `../Tkach Security — MASTER_MANDATE.md`;
5. current product, architecture, security, and threat-model documents;
6. `ROADMAP.md`;
7. `EVIDENCE.md` and `DEVELOPMENT.md` as evidence/history only.

`../Tkach Security — MASTER_MANDATE.md` is the only permanent project
constitution. Phase instructions, temporary deferrals, old stop conditions,
and historical acceptance records do not become permanent bans.

## Implemented product boundary

The workspace contains three Rust crates:

- `tkach-core`: provider-independent typed security domain, Krosna policy
  evaluation, Zaslon hard-deny rules, Gnezdo data/control containment,
  Propusk authorization, Niti/Metka lineage and classification, Ruslo flow
  evaluation, Klyuchnik broker boundary, and Sled evidence/testbed;
- `tkach-gateway`: bounded request parsing, provider lifecycle orchestration,
  final release gates, fixed protected-effect executors, authenticated runtime
  lifecycle, loopback length-prefixed transport, cancellation, shutdown, and
  bounded replay/response receipts;
- `tkach-provider-openai`: a non-streaming OpenAI Responses adapter whose
  output remains hostile provider DATA and must pass the Gateway/core gates.

The canonical product vocabulary is:

`Krosna` · `Propusk` · `Ruslo` · `Zaslon` · `Gnezdo` · `Niti` · `Metka` ·
`Klyuchnik` · `Sled`.

No deprecated primitive name, provider SDK, MCP adapter, streaming release
API, generic executor, public internet gateway, UI, or cloud control plane is
implemented at this baseline.

## Security boundary that exists

The strongest implemented local path is:

```text
bounded authenticated loopback frame
  -> RuntimeService / Gateway
  -> untrusted provider DATA and typed proposals
  -> Zaslon + Gnezdo + Niti/Metka
  -> Krosna + Ruslo
  -> kernel-issued Propusk
  -> fixed RealEffectExecutor / Klyuchnik
  -> bounded receipt and release
```

Authentication identifies the runtime caller; it does not authorize model
actions. A raw `ActionRequest` is not execution authority. Real effects are
limited to the reviewed fixed local file bindings and configured non-zero
loopback HTTP destination. The runtime listener is a local carrier, not TLS,
process isolation, durable distributed replay, or a public gateway.

The core is frozen by default. Change a core primitive only for a concrete,
reproducible security or product defect with an independent regression test.

## Evidence status

PROVEN by local evidence:

- deterministic fail-closed policy and directional flow decisions;
- hard-deny canonicalization and streaming-boundary behavior;
- DATA/CONTROL containment and no model-minted authority;
- scoped Propusk-only execution;
- conservative Niti/Metka propagation and denied self-declassification;
- opaque broker handles, payload-free evidence, and zeroize-on-drop broker
  storage;
- private, bounded, redacted runtime authentication proof storage that is
  zeroized when its authenticator is dropped;
- private, redacted OpenAI adapter credential storage that is zeroized when its
  trusted configuration is dropped; transient HTTP-client/header and
  caller-owned buffers remain outside this ownership guarantee;
- bounded hostile-provider Gateway workflows and real fixed filesystem/
  loopback effects;
- authentication-before-Gateway admission, replay rejection, cancellation,
  shutdown, explicit `FAILED_BEFORE_EFFECT`/`OUTCOME_UNKNOWN`, and bounded
  transport receipts;
- useful Basic, Controlled, Sealed, coding-agent, protected-read, internal
  summary, and exact local-effect workloads with zero defined false allows and
  zero defined false denies in the declared test environment.

PARTIAL or deployment-dependent:

- no-follow and path-substitution resistance where the portable API cannot
  provide universal handle-relative transactions;
- authentication trust, TLS/IPC, OS/process/ACL isolation, core-dump policy,
  secret injection, and durable replay; the trusted in-process authentication
  proof is zeroized on authenticator drop, but caller-owned frame buffers are
  outside that guarantee;
- protection from same-privilege out-of-band effects or a compromised host;
- real-provider availability and behavior beyond the offline adapter tests.

UNPROVEN at this baseline:

- universal concurrent filesystem race prevention on every supported platform;
- durable or distributed exactly-once effects;
- forceful interruption of blocking synchronous provider/OS calls;
- libFuzzer execution on this Windows MSVC host;
- semantic prompt-injection detection or perfect semantic taint analysis.

## Validation baseline

The final production-runtime local evidence passed:

- formatting, workspace clippy with warnings denied, debug/release workspace
  tests, documentation tests and rustdoc with warnings denied;
- locked metadata, offline `cargo audit --no-fetch`, `cargo deny check`,
  offline fuzz-binary compilation, offline packaging, and Quickstart execution;
- 113 core, 9 composition, 9 independent-oracle, 49 Gateway unit, 25 Gateway
  boundary, 14 product-proof, 13 real-effect, 34 provider, and 1 opt-in live
  guard tests in the debug/release matrix;
- targeted runtime mutation: 110 mutants, 85 caught, 24 unviable, and one
  diagnostic-only `Visitor::expecting` survivor; no security-path survivor;
- fuzz targets compile; execution is unavailable under this Windows linker and
  is not claimed as executed.

The source baseline is tagged locally as `production-runtime-v0.1`. Existing
local evidence tags also include `strong-core-v0.1`, `gateway-v0.1`,
`openai-provider-v0.1`, `product-proof-v0.1`, `integration-proof-v0.1`, and
`production-boundary-v0.1`.

Codex Security scans: INCONCLUSIVE / unavailable due to stalled external tooling; not used as security evidence.

The existing `threat_model` and `preflight` handles remain running without
terminal artifacts. They are neither PASS nor security evidence; no new scan
is started and no existing scan is canceled.

## Current phase

The current phase is repository/documentation shape cleanup after the local
production-runtime baseline. The next engineering boundary is selected from
residual risks and integration evidence in `ROADMAP.md`; no speculative
provider, SDK, UI, cloud, or MCP implementation is implied by this baseline.

Historical checkpoints and reports remain valuable evidence, but they are not
active mandates. `DEVELOPMENT.md` is the concise chronological engineering
record and `EVIDENCE.md` is the consolidated validation record.
