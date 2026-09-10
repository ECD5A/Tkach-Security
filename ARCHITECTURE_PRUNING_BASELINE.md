# Architecture Pruning Baseline

This document freezes the security and engineering baseline before the
Architecture Pruning & Product Contract Review. It is evidence for A0, not a
replacement for the permanent mandate or the Strong Core/Gateway/provider
threat models.

## Frozen revision

- Repository: `Tkach Security`
- HEAD: `59142d8360ca5487cb15a56b19c75da6213124fa`
- Baselines: `strong-core-v0.1`, `gateway-v0.1`, `openai-provider-v0.1`
- Worktree: clean before this review
- Network push: not performed

## Security properties that must survive

- Krosna is the deterministic authorization decision point; unknown or
  malformed privileged state denies.
- Propusk is the only accepted protected-executor authority and is bound to
  principal, operation, capability, and exact resource scope.
- READ and EXPORT are distinct Diode decisions; protected-derived public
  export is denied.
- Gnezdo keeps untrusted content in DATA and exposes no public DATA-to-CONTROL
  constructor.
- Niti and Metka preserve provenance and conservative classification; model
  output cannot self-declassify.
- Pechat keeps broker-held raw values outside normal model-visible structures;
  reveal is denied and secret use requires an exact Propusk route.
- Zaslon is a deterministic hard boundary for configured content/action rules,
  including bounded stream semantics and explicit finish.
- Sled is payload-free diagnostic evidence and is not deserializable authority.
- Gateway input, lifecycle, staging, tool, replay, and egress boundaries are
  bounded and fail closed.
- OpenAI adapter credentials remain trusted configuration; provider data cannot
  mint authority, access executor/Pechat, or bypass Gateway/Core egress gates.

## Test and security baseline

The frozen HEAD passed the following before pruning:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo test --workspace --all-targets --all-features --locked`
- `cargo test --workspace --release --all-targets --all-features --locked`
- `cargo audit --no-fetch`
- `cargo deny check`
- `cargo check --manifest-path fuzz/Cargo.toml --bins --locked --offline`
- `git diff --check`

The workspace test baseline was 208 passing tests in both debug and release
profiles: 112 core unit tests, 9 core composition tests, 9 independent-oracle
tests, 19 Gateway unit tests, 25 Gateway boundary tests, 33 OpenAI provider
unit tests, and 1 opt-in live-test guard. The live guard performed no network
request without explicit opt-in.

The final OpenAI mutation baseline covered 201 mutants: 158 caught, 29
unviable, 1 intentionally hostile timeout, and 13 classified survivors. No
unexplained security-relevant survivor remained. Dependency gates reported no
advisories; `cargo deny` emitted only duplicate `syn` and `windows-sys`
version warnings.

## Baseline size snapshot

Counts use repository-tracked production Rust files under `crates/*/src`,
direct workspace manifests, and a deterministic `rg` public-item inventory.
They are comparison measures, not optimization targets.

| Metric | Before pruning | Counting rule |
| --- | ---: | --- |
| Production crates | 3 | Workspace members; `fuzz` is excluded |
| Production Rust files | 21 | Tracked `crates/*/src/*.rs` |
| Production Rust LOC | 12,966 | Physical lines in those files |
| Approximate public declaration/field lines | 372 | `rg` inventory; reviewed manually before changing API |
| Unique direct normal dependency names | 7 | Includes internal workspace dependencies |
| Production workspace crates with network code | 1 | OpenAI adapter only; bounded non-streaming transport |

## A0 decision rule

Every removal, merge, or visibility reduction must state which property above
survives and must add or update a regression test when behavior or an exposed
boundary changes. A candidate is kept when its deletion would remove a real
runtime enforcement mechanism, a required integration boundary, or a test
that proves a security invariant.
