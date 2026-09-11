# Distribution contract

This is the compact release runbook for the frozen Strong Core candidate. It
describes what is prepared locally and what still requires an explicit release
owner action. It is not a publication log.

## Version and package contract

The workspace uses SemVer and MSRV Rust 1.85. The seven packages inherit the
repository, homepage, Apache-2.0 license, root README, and discovery keywords:

1. `tkach-core`
2. `tkach-gateway`
3. `tkach-http`
4. `tkach-client`
5. `tkach-mcp`
6. `tkach-cli`
7. `tkach-provider-openai`

The publication order follows dependency direction. A release must use one
clean versioned tag, a locked dependency graph, passing CI, and matching
release notes. A breaking public contract requires a deliberate SemVer major
change; compatible additions use a minor release; security and documentation
fixes use a patch release unless the contract requires otherwise.

## Local release preflight

Run from a clean checkout with the pinned toolchain:

```text
cargo fmt --all -- --check
cargo metadata --format-version=1 --locked --no-deps
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --release --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo doc --workspace --all-features --no-deps --locked
cargo audit
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
cargo package --workspace --locked
cargo run -p tkach-gateway --example quickstart --locked
python -m unittest discover -s tools/release -p "test_*.py" -v
```

The release process must additionally verify the exact tag, clean worktree,
artifact checksums, and a fresh install of the CLI and MCP adapter. The tag
workflow installs both with `cargo install --locked --root` into an isolated
runner directory, checks `tkach --version`, and feeds clean EOF to the MCP
binary. LibFuzzer execution and cross-platform artifact execution are
release-environment gates; the Windows development host only proves target
compilation.

`.github/workflows/release.yml` performs this release-environment preflight only
for a strict `vX.Y.Z` tag. It builds Linux x86_64, macOS x86_64/ARM64, and
Windows x86_64 archives for `tkach` and `tkach-mcp`, emits SHA-256 files,
uses `tools/release/package_release.py` to fix archive metadata to the source
commit epoch, requests GitHub build provenance, and creates a draft GitHub
Release after checksum verification. The helper's tests prove byte-stable
archives for identical inputs; this does not claim byte-identical Rust
binaries across different toolchains or operating systems. The workflow does
not publish a public release automatically.

## Artifact and integration boundaries

The first useful binary is `tkach`, which provides bounded onboarding and a
deterministic demo. `tkach serve --demo` is a loopback-only reference runtime
for local HTTP smoke tests; it accepts its bearer token only from trusted
environment configuration and contains no real provider or effect integration.
`tkach-mcp` is a stdio adapter over an already running loopback Tkach HTTP
runtime. `tkach-http` remains a library boundary, not a production server
binary. Consequently this repository does not yet claim a ready-to-run public
HTTP service, TLS termination, process supervisor, or OCI image. Creating
those artifacts without those boundaries would overstate the security contract.

The HTTP JSON contract is the language-neutral integration point. Source-level
standard-library Python, dependency-free Node.js/TypeScript, and Go adapters
are included under `sdk/`. None of
these adapters may duplicate Core policy, authority, provider, executor, or
secret-handling logic. The Python and Node adapters include local package
metadata and are checked as installable source bundles; no Python, npm, or Go
package has been published.

## MCP Registry readiness gate

The MCP adapter is not registered in the Official MCP Registry. Registration
is intentionally deferred until the server has a public, installable package
and a versioned release that can be independently verified. The current
`tkach-mcp` binary is a local stdio adapter that requires an already-running
loopback Tkach runtime and a locally supplied bearer token; publishing its
metadata now would make installation and operational readiness look stronger
than they are.

When that boundary is ready, the release owner must use the current official
Registry workflow rather than hand-editing registry data:

1. publish and verify the installable MCP package or release artifact;
2. create and validate `server.json` with the official `mcp-publisher` CLI;
3. authenticate the package namespace and repository ownership;
4. publish through `mcp-publisher publish` and verify the returned Registry
   record.

The authoritative workflow and schema are maintained by the
[MCP Registry publishing guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/quickstart.mdx),
the [publisher CLI reference](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/cli/commands.md),
and the [official Registry API documentation](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md).
No Registry credentials are stored in this repository, and no publication was
attempted during local development.

## External publication status

Not performed in this workspace:

- crates.io publication;
- signed GitHub Release binaries;
- Docker/OCI publication;
- MCP Registry registration.

Those actions require owner-controlled credentials, repository settings, a
reviewed release tag, and final platform/registry verification. This runbook
describes release work; it does not grant publication authority.
