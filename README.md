# Tkach Security

Tkach Security is a provider-independent deterministic security layer for
systems that surround probabilistic models. The model proposes; Tkach
authorizes.

The current autonomous scope is the Strong Core only. It deliberately excludes
LLM providers, MCP, network services, SDKs, cloud integrations, and UI.

## Repository map

- `crates/tkach-core` — typed security kernel and primitives.
- `ARCHITECTURE.md` — implemented architecture and trust boundaries.
- `SECURITY_MODEL.md` — guarantees, assumptions, non-guarantees, and limits.
- `THREAT_MODEL.md` — threats and expected containment behavior.
- `ROADMAP.md` — mandate state.
- `DEVELOPMENT.md` — concise engineering continuity record.
- `Tkach Security — MASTER_MANDATE.md` — permanent engineering constitution.

## Validation

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --locked
cargo audit
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
```

The core is synchronous, deterministic, network-independent, and forbids
`unsafe` Rust. CI also runs a bounded libFuzzer smoke target on Linux.
