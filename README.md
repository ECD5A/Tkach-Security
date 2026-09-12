<p align="right">
  <a href="README.ru.md">Русская версия</a>
</p>

<p align="center">
  <img src="assets/tkach-preview.png" alt="Tkach Security — Krosna, Zaslon, Propusk and Sled">
</p>

<div align="center">

**A fail-closed security boundary for AI agents and compromised model output.**

<a href="https://github.com/ECD5A/Tkach-Security/actions/workflows/ci.yml"><img src="https://github.com/ECD5A/Tkach-Security/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
<a href="https://github.com/ECD5A/Tkach-Security/releases/tag/v0.1.0"><img src="https://img.shields.io/github/v/release/ECD5A/Tkach-Security?display_name=tag&sort=semver" alt="GitHub release"></a>
<a href="https://www.npmjs.com/package/tkach-security-client"><img src="https://img.shields.io/npm/v/tkach-security-client?logo=npm" alt="npm package"></a>
<a href="https://crates.io/crates/tkach-cli"><img src="https://img.shields.io/crates/v/tkach-cli?logo=rust" alt="tkach-cli on crates.io"></a>
<img src="https://img.shields.io/badge/MSRV-1.85-orange?logo=rust" alt="MSRV 1.85">
<img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache 2.0 license">

</div>

Tkach Security is a deterministic typed boundary around systems that use
probabilistic or compromised models.

> The model proposes. Tkach authorizes.

Model output remains untrusted DATA. Tkach prevents it from minting authority,
crossing protected information-flow boundaries, or using brokered secrets as
ordinary context. It does not attempt to make a model trustworthy.

## Why Tkach

- Model text and tool proposals cannot mint execution authority.
- Protected effects require an exact-scope, kernel-issued `Propusk`.
- `READ`, `EXPORT`, and other directions are separate `Ruslo` decisions.
- `Gnezdo`, `Niti`, and `Metka` retain conservative data and provenance state.
- `Zaslon` and final release gates fail closed on malformed, over-limit, denied,
  replayed, cancelled, or uncertain states.
- `Klyuchnik` keeps broker-held secret values outside ordinary model-visible
  context; `Sled` records bounded, payload-free evidence.

This secures the enforcement path when the model is hostile. An integrator that
routes around Tkach is outside that boundary.

## Golden Case

The offline proof needs no model, network, or real effect:

```console
cargo run -p tkach-gateway --example golden_case --locked
GOLDEN_CASE|safe_output=released|compromised_action=denied|executor_calls=0
```

Useful bounded output is released. A compromised provider's protected-write
proposal is denied before the executor is invoked. This is a deterministic
boundary proof, not a claim of universal prompt-injection detection or host
compromise protection.

## Start in minutes

Install from crates.io with Rust 1.85 or newer:

```console
cargo install tkach-cli --locked
tkach init my-agent
tkach check my-agent/.tkach/request.json
tkach run --demo
```

`init` refuses to overwrite an existing request; `check` validates the strict
Gateway shape; `run --demo` proves the local fail-closed path.

You can also download a verified binary archive for Linux, macOS, or Windows
from the [v0.1.0 release](https://github.com/ECD5A/Tkach-Security/releases/tag/v0.1.0).
Each archive has a SHA-256 manifest, keyless Sigstore bundle, and GitHub build
attestation. See the [distribution guide](docs/DISTRIBUTION.md) before using a
release artifact.

The thin Node.js/TypeScript carrier is available from npm:

```console
npm install tkach-security-client
```

## Integrate without moving policy out of Rust

`tkach-core` stays provider-, protocol-, and language-independent. The CLI,
local HTTP contract, Rust client, Python/JavaScript/Go carriers, and MCP stdio
server are adapters around that Core; none defines a second policy engine.

For the exact CLI, TUI, local `serve` lifecycle, HTTP, MCP, container, and
language-adapter instructions, use the [integration guide](docs/INTEGRATION.md).
Copyable end-to-end commands are in [`examples/`](examples/).

<details>
<summary>Show the cross-platform CLI window</summary>

<p align="center">
  <img src="assets/tkach-cli-en.png" width="100%" alt="Tkach CLI in English on WSL Ubuntu">
</p>
</details>

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
     flow gates         |
          |             v
          +----> protected executor
                         |
                         v
              final Zaslon/Ruslo release
                         |
                         v
                 bounded Sled receipt
```

## v0.1.0 release status

- Seven Rust crates are published on crates.io: `tkach-core`, `tkach-gateway`,
  `tkach-http`, `tkach-client`, `tkach-mcp`, `tkach-cli`, and
  `tkach-provider-openai`.
- `tkach-security-client@0.1.0` is published on npm.
- The public GitHub release contains signed, attested Linux x86_64, macOS
  x86_64/aarch64, and Windows x86_64 CLI archives.
- The hosted release matrix built and tested Linux, macOS, Windows, OCI smoke,
  checksum, keyless Sigstore, and GitHub attestation paths.
- `tkach-mcp@0.1.0` is registered in the Official MCP Registry as
  `io.github.ECD5A/tkach-security` for local stdio use.
- The multi-arch OCI image was pushed to GHCR, attested, and made public by the
  repository owner for anonymous pulls.

Tkach does **not** claim a public internet gateway, TLS termination, a PyPI
package, Streamable HTTP, a cloud control plane, or a generic executor. The
OCI image is distributable, but the runtime remains loopback-only by default;
deployment beyond that boundary is an explicit integrator decision.

## Documentation

- [Product contract](docs/PRODUCT_CONTRACT.md) — guarantees and deployment conditions.
- [Architecture](docs/ARCHITECTURE.md) — boundaries and trusted computing base.
- [Security model](docs/SECURITY_MODEL.md) and [threat model](docs/THREAT_MODEL.md).
- [Integration guide](docs/INTEGRATION.md) — CLI, HTTP, MCP, containers, and adapters.
- [Examples](examples/) — Rust, HTTP, Python, JavaScript, Go, and MCP paths.
- [Distribution](docs/DISTRIBUTION.md) and [v0.1.0 release notes](docs/releases/v0.1.0.md).
- [Security policy](SECURITY.md), [contributing](CONTRIBUTING.md), and [changelog](CHANGELOG.md).

## Contributing

Keep changes small and explicit about the security boundary. Core changes need
a demonstrated security or product defect; adapters must remain thin and must
not duplicate Core logic. See [CONTRIBUTING.md](CONTRIBUTING.md) for required
checks, public-claim rules, and files that must remain local.

## Support

If Tkach Security is useful to your work, support its continued maintenance:

- TON: `pointoncurve.ton`
- Bitcoin (BTC): `1ECDSA1b4d5TcZHtqNpcxmY8pBH1GgHntN`
- USDT (TRC20): `TUF4vPdB6QkjCvZq18rBL4Qj4dK5ihCN75`

## Contact

Questions about Tkach Security, integration, security research, or
collaboration:

<p>
  <a href="mailto:stelmak159@gmail.com" aria-label="Email"><img alt="Email" height="24" src="https://cdn.simpleicons.org/gmail/EA4335"></a>
  &nbsp;
  <a href="https://t.me/ECDS4" aria-label="Telegram"><img alt="Telegram" height="24" src="https://cdn.simpleicons.org/telegram/26A5E4"></a>
  &nbsp;
  <a href="https://github.com/ECD5A/Tkach-Security" aria-label="GitHub repository"><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/github/FFFFFF"><img alt="GitHub repository" height="24" src="https://cdn.simpleicons.org/github/181717"></picture></a>
</p>
