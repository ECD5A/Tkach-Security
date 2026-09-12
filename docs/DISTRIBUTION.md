# Distribution contract

This is the compact release runbook for the frozen Strong Core. It records the
published v0.1.0 distribution boundary and the explicit owner actions still
required for future releases. It is not a substitute for the release log.

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
release notes. Prefer additive changes within the existing contract. During v0.x,
breaking Rust API or wire changes require a deliberate
minor-version change. From v1.0, breaking changes require a major version;
compatible additions use a minor release. Compatible fixes use a patch release.
Every breaking change requires release notes, updated examples, and a fresh
security/regression review. Version changes do not authorize weakening the
security contract.

CI and the tag preflight run `tools/release/check_versions.py` so every Rust
crate, the Python and Node adapters, and the MCP manifest share one exact
version. Go remains module-versioned by its repository release tag.

For the initial registry publication, CI packages the independent
`tkach-core` crate and builds/tests every other workspace crate. Cargo cannot
package the dependent crates against an empty crates.io index: their path
dependencies are rewritten to registry dependencies and must already exist
there. The owner-controlled publication sequence must therefore publish and
verify `tkach-core` first, then package/publish the dependent crates in
dependency order. A pre-publication `cargo package --workspace` gate would be
invalid and is deliberately not used.

## Local release preflight

Run the complete [contributor checks](../CONTRIBUTING.md#required-checks)
and onboarding commands from a clean checkout with the pinned toolchain.
That list is shared with regular development; release-specific gates follow.

For code changes, regular GitHub CI runs the complete Rust build and test suite
on Ubuntu, macOS, and Windows. Documentation, license, and asset-only changes
are intentionally excluded from the code CI trigger; changing workflow files
still runs CI so the gate itself cannot silently drift.

The release process must additionally verify the exact tag, clean worktree,
artifact checksums, and a fresh install of the CLI and MCP adapter. The tag
workflow installs both with `cargo install --locked --root` into an isolated
runner directory, checks `tkach --version`, feeds clean EOF to the MCP binary,
and executes the offline Golden Case. The same release contract compiles the
copyable Python/JavaScript/Go examples. LibFuzzer execution and cross-platform
artifact execution are release-environment gates; the Windows development host
only proves target compilation.

`.github/workflows/release.yml` performs this release-environment preflight only
for a strict `vX.Y.Z` tag. It builds Linux x86_64, macOS x86_64/ARM64, and
Windows x86_64 archives for `tkach` and `tkach-mcp`, emits SHA-256 files,
uses `tools/release/package_release.py` to fix archive metadata to the source
commit epoch, signs archives and checksum manifests with keyless Sigstore via
the exact release workflow identity, verifies those bundles, requests GitHub
build provenance, and creates a draft GitHub Release after checksum
verification. The v0.1.0 draft was manually reviewed and published after its
hosted release jobs passed. The helper's tests prove byte-stable archives for
identical inputs; this does not claim byte-identical Rust binaries across
different toolchains or operating systems. Future public release publication
remains a maintainer action; the workflow never publishes a draft
automatically.

The repository also contains a local multi-stage `Dockerfile`. It builds the
CLI from the locked workspace, runs as a non-root UID, keeps `TKACH_HTTP_ADDR`
loopback-only, and checks `/healthz` through the CLI's bounded `health`
command. Linux host networking is the only documented host-local container
profile; wildcard binds, TLS termination, ingress, and OCI publication remain
separate reviewed boundaries.

## Artifact and integration boundaries

The first useful binary is `tkach`, which provides bounded onboarding and a
deterministic demo. `tkach serve --demo` is a loopback-only reference runtime
for local HTTP smoke tests; it accepts its bearer token only from trusted
environment configuration and contains no real provider or effect integration.
Ordinary `tkach serve` is a local OpenAI-compatible provider runtime with the
same bounded HTTP/auth/health carrier and an explicitly read-only default
effect profile. It is not a public gateway, TLS terminator, supervisor, or
generic executor.
`tkach-mcp` is a stdio adapter over an already running loopback Tkach HTTP
runtime. `tkach-http` remains a library boundary, not a production server
binary. Consequently this repository does not yet claim a ready-to-run public
HTTP service, TLS termination, process supervisor, or published OCI image. The
local image is a private deployment artifact, not a public network gateway.

The HTTP JSON contract is the language-neutral integration point. Source-level
standard-library Python, dependency-free Node.js/TypeScript, and Go adapters
are included under `sdk/`. None of
these adapters may duplicate Core policy, authority, provider, executor, or
secret-handling logic. The thin Node.js/TypeScript adapter is now published as
[`tkach-security-client`](https://www.npmjs.com/package/tkach-security-client)
`0.1.0`; the Python and Go adapters remain source/local packages.

Future npm releases use `.github/workflows/publish-npm.yml` with GitHub OIDC
and direct npm publishing. The package's Trusted Publisher must be configured
for GitHub user `ECD5A`, repository `Tkach-Security`, workflow filename
`publish-npm.yml`, and environment `npm-publish`; direct `npm publish` must be
allowed for this workflow. The workflow is tag-only, runs the package tests,
prints the exact package contents, attaches npm provenance, and skips an
already published version instead of attempting a duplicate upload. The
environment must not have unreviewed workflows or untrusted branches attached
to it; tag protection remains the release authorization boundary.

## MCP Registry readiness gate

The MCP adapter is not registered in the Official MCP Registry. The matching
`tkach-mcp@0.1.0` crate and the repository are public, but the binary remains
a local stdio adapter that requires an already-running loopback Tkach runtime
and a locally supplied bearer token. Registry metadata would otherwise make
installation and operational readiness look stronger than they are, so
registration remains intentionally deferred.

When that boundary is ready, the release owner must use the current official
Registry workflow rather than hand-editing registry data:

1. verify the installable `tkach-mcp` Cargo package and its release artifact;
2. validate the repository `server.json` with the official
   `mcp-publisher validate` command;
3. authenticate the package namespace and repository ownership;
4. publish through `mcp-publisher publish` and verify the returned Registry
   record.

The manifest uses the current Cargo package contract and the visible
`mcp-name: io.github.ECD5A/tkach-security` marker in the crate README. It is
not evidence of Registry publication or turnkey hosted operation.

The authoritative workflow and schema are maintained by the
[MCP Registry publishing guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/quickstart.mdx),
the [publisher CLI reference](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/cli/commands.md),
and the [official Registry API documentation](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md).
No Registry credentials are stored in this repository, and no publication was
attempted during local development.

## External publication status

Completed:

- all seven Rust crates at version `0.1.0` on crates.io;
- public npm publication of `tkach-security-client@0.1.0`;
- the public [v0.1.0 GitHub Release](https://github.com/ECD5A/Tkach-Security/releases/tag/v0.1.0)
  with Linux x86_64, macOS x86_64/aarch64, and Windows x86_64 archives,
  SHA-256 manifests, keyless Sigstore bundles, and GitHub attestations.

Not performed yet:

- Docker/OCI publication;
- MCP Registry registration.

Those actions require owner-controlled credentials, reviewed deployment
boundaries, and final platform/registry verification. This runbook describes
release work; it does not grant publication authority.

### v0.1.0 Windows archive note

The v0.1.0 Windows ZIP stores valid PE binaries as `tkach` and `tkach-mcp`
without the conventional `.exe` suffix. They can be started through an explicit
path, but that does not meet the expected Windows extraction UX. The release
workflow is regression-fixed for the next release; until that release exists,
Windows users can install `tkach-cli` from crates.io instead.
