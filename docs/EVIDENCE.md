# Security and Validation Evidence

This is the single evidence record for the current repository. Source code and
executable tests remain authoritative; this document records what was run,
what it establishes, and what it does not establish. Older phase reports were
consolidated here and removed from the active tree.

## Current result

The local implementation has zero defined false allows and zero defined false
denies for the declared Basic, Controlled, Sealed, coding-agent, protected-read,
internal-summary, and exact local-effect workloads in the offline testbed.
Hostile provider, malformed input, replay, cancellation, protected export,
secret reveal, scope widening, parser ambiguity, and final-release paths are
tested as terminal or denied outcomes.

The trusted runtime authentication proof is now owned by
`zeroize::Zeroizing<Vec<u8>>`; code review and the existing redaction/boundary
tests establish private storage and the drop-time cleanup contract. A safe
portable test cannot inspect freed memory, so this is not reported as a
memory-forensics proof. Caller-owned frame buffers, host memory, and core dumps
remain outside the claim.

## Local validation matrix

The required local commands are:

```text
cargo fmt --all -- --check
cargo metadata --format-version=1 --locked --no-deps
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --release --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
RUSTDOCFLAGS=-D warnings cargo doc --workspace --all-features --no-deps --locked
cargo audit --no-fetch
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --bins --locked --offline
cargo package --workspace --allow-dirty --no-verify --offline
cargo run -p tkach-gateway --example quickstart --locked
```

The current debug/release workspace matrix contains 266 passing tests:

| Suite | Tests |
| --- | ---: |
| Core unit | 113 |
| Core composition | 9 |
| Core independent oracle | 9 |
| Gateway unit | 49 |
| Gateway boundary | 25 |
| Product proof | 14 |
| Real effects | 13 |
| OpenAI provider | 33 |
| Opt-in live guard | 1 |

The same suites pass in both debug and release profiles. The docs, packaging,
Quickstart, audit, deny, metadata, formatting, and clippy gates pass locally.
Fuzz binaries compile with locked offline dependencies; libFuzzer execution is
not claimed on this Windows MSVC host. The ignored `target/` and
`fuzz/target/` directories are generated artifacts, not repository inputs.

## Adversarial and mutation evidence

- Core composition and independent-oracle tests cover authority laundering,
  forged provenance, unknown state, direction confusion, secret routes, and
  exact bounds.
- Gateway boundary and product-proof tests cover hostile providers, useful
  legitimate workflows, false-allow/false-deny counters, replay, failure,
  timeout, cancellation, premature release, and protected local effects.
- Targeted runtime mutation evidence covered 110 mutants: 85 caught, 24
  platform/build-unviable, and one diagnostic-only `Visitor::expecting`
  survivor. No security-path mutant survived.
- Earlier pruning red-team evidence found no surviving security regression after
  removing only the vocabulary-only `DataLane`, empty `Klyuchnik` facade, and
  `ScriptedProvider` alias. The actual Gnezdo, broker, provider, and executor
  boundaries remain.

## PROVEN / PARTIAL / UNPROVEN

PROVEN by local evidence:

- deterministic fail-closed authorization and directional flow control;
- Zaslon canonicalization, action/content hard denies, and terminal stream
  behavior;
- Gnezdo DATA containment, Niti/Metka conservation, Propusk-only execution,
  Klyuchnik secret isolation, payload-free Sled evidence;
- bounded hostile-provider Gateway behavior and fixed real local effects;
- authentication-before-Gateway admission, replay rejection, cancellation,
  shutdown, explicit uncertain outcomes, and bounded receipts;
- the useful workload and zero-defined-false-allow/deny results above.

PARTIAL or deployment-dependent:

- no-follow/path-substitution resistance where portable Rust cannot provide a
  universal handle-relative transaction;
- runtime caller trust, TLS/IPC, OS/process/ACL isolation, core-dump policy,
  secret injection, durable replay, and protection from same-privilege bypass;
- real provider availability and behavior beyond offline adapter tests.

UNPROVEN:

- universal concurrent filesystem race prevention;
- durable/distributed exactly-once effects;
- forceful interruption of blocking synchronous provider/OS calls;
- libFuzzer execution on this Windows linker;
- semantic prompt-injection detection or perfect semantic taint analysis.

## External tooling limitation

Codex Security scans: INCONCLUSIVE / unavailable due to stalled external tooling; not used as security evidence.

The existing handles `b8e5aaa2...` (`threat_model`) and `7d49ba8c...`
(`preflight`) remain stalled without terminal artifacts. They are not PASS and
their interim zero-finding state is not evidence. No new external scan is
started and no existing scan is canceled.

## Historical tags retained in Git

The detailed phase documents were evidence duplicates, not active mandates.
Their milestones remain recoverable from Git history and tags:

`strong-core-v0.1`, `gateway-v0.1`, `openai-provider-v0.1`,
`product-proof-v0.1`, `integration-proof-v0.1`, `production-boundary-v0.1`,
and `production-runtime-v0.1`.

The current working tree must remain free of build output and credentials.
Every future phase updates this file only after the code, tests, adversarial
review, documentation, and local commit are complete.

## Consolidation map

The following former documents were redundant phase records, so their current
security content is retained in the named documents rather than duplicated:

| Former set | Current home |
| --- | --- |
| architecture cost, pruning baseline/metrics, dependency review, simplification red-team | `ARCHITECTURE.md` and this evidence record |
| primitive review and security value map | `SECURITY_MODEL.md` |
| Gateway, provider, runtime, and isolation threat models; Gateway hardening record | `THREAT_MODEL.md` and `SECURITY_MODEL.md` |
| Quickstart and real-effect contract | `INTEGRATION.md` |
| product-proof benchmark/report/checkpoints and integration checkpoint | executable tests, `SECURITY_MODEL.md`, and this evidence record |
| production-boundary/runtime reports and checkpoints | `CURRENT_BASELINE.md` and this evidence record |
| release plan | `ROADMAP.md` |

The deleted files remain recoverable from Git history; no Rust source, test,
fixture, fuzz target, CI workflow, lockfile, or security control was deleted.
