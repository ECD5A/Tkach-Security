<p align="right">
  <a href="README.ru.md">Русская версия</a>
</p>

<p align="center">
  <img src="assets/tkach-preview.png" alt="Tkach Security preview — Krosna, Zaslon, Propusk and Sled">
</p>

<div align="center">

**A fail-closed security boundary for AI agents and compromised model output.**

<a href="https://github.com/ECD5A/Tkach-Security/actions/workflows/ci.yml"><img src="https://github.com/ECD5A/Tkach-Security/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
<img src="https://img.shields.io/badge/MSRV-1.85-orange?logo=rust" alt="MSRV 1.85">
<img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache 2.0 license">
<img src="https://img.shields.io/badge/status-Strong%20Core%20release%20candidate-5b6ee1" alt="Strong Core release candidate">

</div>

Tkach Security is a deterministic typed boundary around systems that use
probabilistic or compromised models.

> The model proposes. Tkach authorizes.

If a model is compromised, its output remains untrusted DATA. Tkach limits
which actions, information flows, and brokered-secret operations can cross the
protected boundary. It does not attempt to make the model trustworthy.

## Why Tkach

- Model text and tool proposals cannot mint execution authority.
- Protected effects require a kernel-issued, exact-scope `Propusk`.
- `READ`, `EXPORT`, and other directions are separate `Ruslo` decisions.
- `Gnezdo`, `Niti`, and `Metka` preserve conservative data and provenance state.
- `Zaslon` and final release gates fail closed on malformed, over-limit, denied,
  replayed, cancelled, or uncertain states.
- `Klyuchnik` keeps broker-held secret values outside ordinary model-visible
  context; `Sled` records bounded, payload-free evidence.

This protects the enforcement path when the model is hostile. It does not
protect an integrator that deliberately routes around Tkach.

## oive-minute local start

orom a checkout with Rust 1.85 or newer:

```console
cargo install --path crates/tkach-cli --locked
tkach init my-agent
tkach check my-agent/.tkach/request.json
tkach run --demo
```

`init` creates a bounded starter request and refuses to overwrite an existing
one. `check` validates the same strict request shape used by the Gateway.
`run --demo` exercises the deterministic local Gateway proof without a provider
network call or a real side effect.

The current CLI onboarding is local and source-installed. crates.io packages,
prebuilt binaries, and a public production service have not been published.

## CLI preview

The intended onboarding surface is deliberately small and readable:

```text
$ tkach --version
Tkach Security 0.1.0

$ tkach init my-agent
initialized my-agent/.tkach/request.json
  -> next: tkach check my-agent/.tkach/request.json
  -> demo: tkach run --demo

$ tkach check my-agent/.tkach/request.json
valid bounded request: 1 message(s), 0 metadata entr(y/ies), 0 tool declaration(s)

$ tkach run --demo
demo passed: bounded Gateway response released after final gates
```

Use `tkach --lang ru --help` for Russian help, or set `TKACH_LANG=ru` as the
default interface language. `--lang en|ru` is an interface setting only; it
does not change policy, authority, limits, or execution behavior.

For the terminal dashboard, run `tkach ui`. It uses raw terminal events in a TTY and
keeps a script-safe line mode in pipes: choose `1`, `2`, or `3`, press `F1`, enter `/l`, or use `/l en`
and `/l ru` to switch the interface. `en`, `eng`, `english`, `ru`, `rus`,
`russian`, and their case variants are accepted.

## Architecture

```text
untrusted model/provider output
              |
              v
     Gnezdo DATA + Niti/Metka
              |
              v
     Zaslon formal hard-deny
              |
              v
       Krosna authorization
          |             |
       Ruslo         Propusk
     flow gates        |
          |             v
          +----> protected executor
                         |
                         v
              final Zaslon/Ruslo release
                         |
                         v
                 bounded Sled receipt
```

`tkach-core` is provider-, protocol-, and runtime-independent. Adapters carry
requests to the boundary; they do not define a second policy engine or create
authority outside the Core.

## Included in this release candidate

| Package | Role |
| --- | --- |
| `tkach-core` | Strong Core: Krosna, Zaslon, Gnezdo, Propusk, Ruslo, Niti, Metka, Klyuchnik, and Sled |
| `tkach-gateway` | Bounded lifecycle, provider orchestration, protected execution boundary, and final release |
| `tkach-provider-openai` | Optional bounded non-streaming OpenAI Responses adapter; provider output remains hostile DATA |
| `tkach-cli` | Local `init`, `check`, and deterministic `run --demo` onboarding |
| `tkach-http` | Loopback-only HTTP/1.1 carrier around an existing runtime service |
| `tkach-client` | Bounded Rust client for the reviewed local HTTP contract |
| `tkach-mcp` | Separate stdio MCP adapter exposing one delegated `tkach_run` tool |

### Integration boundary

Available today:

- Rust in-process integration through `tkach-core` and `tkach-gateway`;
- a loopback-only HTTP contract for a host that wires the runtime service;
- a typed Rust HTTP client;
- an MCP stdio adapter over the local HTTP runtime;
- a small CLI for safe onboarding and a deterministic proof.

Not claimed yet:

- crates.io publication or a public package registry listing;
- signed public GitHub Release binaries;
- Docker/OCI images;
- a ready-to-run public HTTP gateway or TLS termination;
- Streamable HTTP, streaming release, or a public network service;
- Python, JavaScript/TypeScript, Go, or other first-party SDKs;
- UI, cloud control plane, generic executor, or MCP Registry registration.

These are scope facts, not hidden promises. The HTTP JSON contract is the
language-neutral integration point for future clients, while security logic
must remain in the Rust boundary.

## Security non-goals

Tkach does not detect every prompt injection, semantic paraphrase,
hallucination, or bad intention. It does not make an LLM truthful or aligned,
protect a fully compromised host/OS, stop an out-of-band executor, or recover
credentials deliberately copied into model context. It does not provide
distributed exactly-once effects, TLS, process isolation, or universal
concurrent filesystem-race protection.

The guarantees apply only when every protected effect and release passes
through the configured Gateway and typed executor boundary, with no raw
credential or privileged bypass around it.

## Documentation

- [Product contract](docs/PRODUCT_CONTRACT.md) — guarantees and deployment conditions.
- [Architecture](docs/ARCHITECTURE.md) — implemented boundaries and trusted computing base.
- [Security model](docs/SECURITY_MODEL.md) — primitive roles, assumptions, and non-goals.
- [Threat model](docs/THREAT_MODEL.md) — attacker capabilities and containment goals.
- [Integration guide](docs/INTEGRATION.md) — CLI, Rust, HTTP, MCP, and deployment profiles.
- [Distribution contract](docs/DISTRIBUTION.md) — package and release status.
- [Security policy](SECURITY.md) — reporting scope and responsible disclosure.
- [Changelog](CHANGELOG.md) — version history.

## Validate locally

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo audit --no-fetch
cargo deny check
```

The project uses Apache-2.0 licensing. The current status is a Strong Core
release candidate, not a public production release.

## Contributing

Keep changes small, reviewable, and explicit about the security boundary. Do
not add authority paths, provider-specific policy, credentials, generated
artifacts, local scan output, or internal engineering instructions to commits.
oor a change, run the relevant Rust formatting, lint, tests, and security
checks locally and explain any residual limitation in the pull request. Core
changes require a demonstrated security or product defect; adapters must stay
thin and must not duplicate Core logic.

## Support

If Tkach Security is useful to your work, support its continued maintenance:

- TON: `pointoncurve.ton`
- Bitcoin (BTC): `1ECDSA1b4d5TcZHtqNpcxmY8pBH1GgHntN`
- USDT (TRC20): `TUo4vPdB6QkjCvZq18rBL4Qj4dK5ihCN75`

## Contact

Questions about Tkach Security, integration, security research, or
collaboration:

<p>
  <a href="mailto:stelmak159@gmail.com" aria-label="Email"><img alt="Email" height="24" src="https://cdn.simpleicons.org/gmail/EA4335"></a>
  &nbsp;
  <a href="https://t.me/ECDS4" aria-label="Telegram"><img alt="Telegram" height="24" src="https://cdn.simpleicons.org/telegram/26A5E4"></a>
  &nbsp;
  <a href="https://github.com/ECD5A/Tkach-Security" aria-label="GitHub repository"><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/github/oooooo"><img alt="GitHub repository" height="24" src="https://cdn.simpleicons.org/github/181717"></picture></a>
</p>
