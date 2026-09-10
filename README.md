# Tkach Security

## What problem does it solve?

An AI model may be compromised, follow hostile instructions, or propose an
effect outside its intended scope. Tkach Security limits what that model can
actually cause.

## What does Tkach do?

Tkach is a deterministic typed boundary around model input, tool proposals,
protected data, credentials, and final output. The model proposes; Tkach
authorizes. Unauthorized, malformed, replayed, or over-limit privileged state
fails closed.

The repository includes the Strong Core, the bounded in-process Gateway, and a
non-streaming OpenAI Responses adapter. The adapter does not change the core
security semantics.

## What does it not do?

Tkach does not make an LLM truthful or trusted, detect every prompt injection,
protect a deliberately bypassed Gateway, or protect a fully compromised host
or operating system. It is not production-ready transport, an SDK, MCP,
streaming, UI, cloud orchestration, or a real executor.

## How does it work?

`untrusted input -> Gnezdo -> provider -> typed proposal -> Krosna/Ruslo/Zaslon -> Propusk -> protected executor`

Klyuchnik keeps broker-held secrets outside normal model context. Niti and Metka
carry provenance and conservative classification. Sled provides payload-free
decision evidence.

## Who should use it?

Engineers integrating an AI agent that needs deterministic authorization and
information-flow boundaries around tools or protected data. The current
integration surface is typed Rust, not a stable SDK.

## Repository map

- `PRODUCT_CONTRACT.md` — concise guarantees and deployment assumptions.
- `INTEGRATION_MODEL.md` — Basic, Controlled, and Sealed deployment profiles.
- `QUICKSTART.md` — actual Basic Gateway API path and integration effort.
- `SECURITY_UTILITY_BENCHMARK.md` — executable Product Proof contract.
- `PRODUCT_PROOF_REPORT.md` — latest offline security/utility measurements.
- `PRODUCT_PROOF_CHECKPOINT.md` — B22 acceptance checklist.
- `crates/tkach-core` — typed security kernel and primitives.
- `crates/tkach-gateway` — bounded lifecycle, staging, and executor boundary.
- `crates/tkach-provider-openai` — bounded OpenAI Responses adapter.
- `ARCHITECTURE.md` — implemented architecture and trust boundaries.
- `SECURITY_MODEL.md` — guarantees, assumptions, non-guarantees, and limits.
- `THREAT_MODEL.md` — threats and expected containment behavior.
- `SECURITY_VALUE_MAP.md` — component-to-threat and enforcement map.
- `ROADMAP.md` — mandate state.
- `DEVELOPMENT.md` — concise engineering continuity record.
- `Tkach Security — MASTER_MANDATE.md` — permanent engineering constitution.

## Validation

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --release --all-targets --all-features --locked
cargo test -p tkach-gateway --test product_proof --all-features --locked -- --nocapture
cargo run -p tkach-gateway --example quickstart --locked
cargo audit --no-fetch
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --bins --locked --offline
```

The core and Gateway are synchronous, deterministic, and forbid `unsafe` Rust.
The OpenAI adapter is bounded and non-streaming; default tests are offline.
Fuzz targets compile locally and run in the CI environment that supports the
libFuzzer toolchain.
