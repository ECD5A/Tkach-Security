# Tkach Security

Tkach Security is a deterministic typed boundary around probabilistic or
compromised models. The model proposes; Tkach authorizes.

## Start here

- [Current baseline](docs/CURRENT_BASELINE.md) — what exists, what is proven,
  and what remains partial or unproven.
- [Product contract](docs/PRODUCT_CONTRACT.md) — guarantees and deployment
  conditions.
- [Integration guide](docs/INTEGRATION.md) — the smallest safe Rust path,
  runtime framing, deployment profiles, and exact local effects.
- [Security model](docs/SECURITY_MODEL.md) — invariants, primitive roles, and
  non-guarantees.
- [Threat model](docs/THREAT_MODEL.md) — attacker capabilities and expected
  containment.
- [Evidence](docs/EVIDENCE.md) — validation matrix, adversarial workload
  results, historical tags, and known tooling limits.
- [Roadmap](docs/ROADMAP.md) — current release state and next decisions.

The permanent project constitution is
[Tkach Security — MASTER_MANDATE.md](Tkach%20Security%20%E2%80%94%20MASTER_MANDATE.md).
The reporting policy is [SECURITY.md](SECURITY.md).

## Five-minute local start

The local CLI onboarding adapter is available from the workspace:

```text
cargo install --path crates/tkach-cli --locked
tkach init my-agent
tkach check my-agent/.tkach/request.json
tkach run --demo
```

`init` creates only a new `.tkach/request.json` starter and never writes
credentials or overwrites an existing starter. `check` applies the same strict
bounded request parser used by the Gateway. `run --demo` exercises the local
deterministic Gateway path without a provider network call or real effect; it
is an onboarding proof, not a general-purpose agent runner. Publication to a
package registry and prebuilt binaries are later distribution steps.

## Implemented boundary

```text
bounded authenticated frame
  -> RuntimeService / Gateway
  -> hostile provider DATA and typed proposals
  -> Gnezdo + Zaslon + Niti/Metka
  -> Krosna + Ruslo
  -> kernel-issued Propusk
  -> fixed protected executor / Klyuchnik
  -> bounded receipt and release
```

The workspace contains three provider-independent Rust boundary crates and two
thin local adapters:

- `tkach-core` — Krosna, Zaslon, Gnezdo, Propusk, Ruslo, Niti, Metka,
  Klyuchnik, and Sled;
- `tkach-gateway` — bounded lifecycle, staging, final release, authenticated
  local runtime, and the narrow real-effect reference boundary;
- `tkach-provider-openai` — a bounded non-streaming OpenAI Responses adapter
  whose output remains untrusted provider DATA.

- `tkach-cli` - the bounded `tkach init`, `check`, and deterministic `run
  --demo` onboarding surface; it adds no authority or security logic.
- `tkach-http` - the loopback-only HTTP/1.1 carrier for an existing
  `RuntimeService`; it adds transport validation, not policy or execution
  authority.

There is no SDK, MCP adapter, streaming release API, public internet gateway,
UI, cloud control plane, or generic executor in the current source surface.
These are current scope facts, not permanent constitutional prohibitions.

## Validation

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --release --all-targets --all-features --locked
cargo audit --no-fetch
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --bins --locked --offline
cargo doc --workspace --all-features --no-deps --locked
cargo package --workspace --allow-dirty --no-verify --offline
cargo run -p tkach-gateway --example quickstart --locked
```

The core and Gateway forbid `unsafe` Rust. Default tests are offline; the
OpenAI live guard is opt-in. Fuzz targets compile locally, while libFuzzer
execution depends on the host toolchain.
