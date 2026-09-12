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
different toolchains or operating systems. Before upload, each native runner
also unpacks its emitted archive and runs `--version` for both CLI binaries;
this catches archive-layout and filename regressions before signing. Future
public release publication remains a maintainer action; the workflow never
publishes a draft automatically.

## Verify a v0.1.0 archive

Download the chosen archive and its adjacent `.sha256` file from the
[v0.1.0 GitHub Release](https://github.com/ECD5A/Tkach-Security/releases/tag/v0.1.0).
Verify the checksum before extraction:

~~~console
# Linux
sha256sum -c tkach-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256

# macOS
shasum -a 256 -c tkach-0.1.0-aarch64-apple-darwin.tar.gz.sha256
~~~

On Windows PowerShell, compare the expected digest with `Get-FileHash`:

~~~powershell
$expected = ((Get-Content -Raw tkach-0.1.0-x86_64-pc-windows-msvc.zip.sha256).Trim() -split '\s+')[0]
$actual = (Get-FileHash tkach-0.1.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256).Hash
if ($actual -ine $expected) { throw "SHA-256 mismatch" }
~~~

Then verify GitHub build provenance for the downloaded file with GitHub CLI:

~~~console
gh attestation verify <archive> \
  --repo ECD5A/Tkach-Security \
  --signer-workflow ECD5A/Tkach-Security/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 \
  --deny-self-hosted-runners
~~~

Successful `gh attestation verify` is intentionally silent unless an output
format is requested. It verifies the GitHub provenance claim; it does not
replace checksum verification. The release also includes matching keyless
Sigstore bundles for users whose deployment policy requires independent
bundle verification.

The repository also contains a multi-stage `Dockerfile`. It builds the CLI from
the locked workspace, runs as a non-root UID, keeps `TKACH_HTTP_ADDR`
loopback-only, and checks `/healthz` through the CLI's bounded `health`
command. Linux host networking is the only documented host-local container
profile; wildcard binds, TLS termination, ingress, and public network exposure
remain separate reviewed boundaries.

The GHCR publication boundary is now encoded in
[`.github/workflows/publish-oci.yml`](../.github/workflows/publish-oci.yml).
It runs only for a published GitHub Release or an explicit manual dispatch,
requires the protected `ghcr-publish` environment, builds `linux/amd64` and
`linux/arm64`, publishes only version and commit-SHA tags (never `latest`), and
attaches GitHub build provenance to the pushed digest. The image remains
non-root and loopback-only. GHCR creates a package as private on first
publication; package visibility is a deliberate owner action in GitHub
Package Settings and is not changed by this workflow. Consumers should pin
the published digest rather than trust a mutable tag.

The v0.1.0 image was built for both supported Linux architectures, pushed, and
attested successfully. Its package is still private until the repository owner
changes visibility at the [GHCR package page](https://github.com/ECD5A/Tkach-Security/packages/container/tkach-security).
The verified multi-arch index is
`ghcr.io/ecd5a/tkach-security@sha256:6e9f7e815a24385ca8e2ed6a3851ca7ab55d48410aad0167a63402149c64ed0f`.
The existing `container` job in `release.yml` remains a build-and-health smoke
gate and does not push.

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
HTTP service, TLS termination, process supervisor, or public OCI image. The
GHCR image is currently a private deployment artifact, not a public network
gateway.

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

The matching `tkach-mcp@0.1.0` crate and the repository are public, and the
Cargo manifest satisfies the current Registry package shape. The adapter is
still a local stdio process that requires an already-running loopback Tkach
runtime and a locally supplied bearer token. That operational prerequisite is
documented in the package README and must remain visible to MCP users; Registry
publication does not turn it into a hosted service.

The adapter is registered as `io.github.ECD5A/tkach-security` in the Official
MCP Registry. The gated publication workflow is encoded in
[`.github/workflows/publish-mcp.yml`](../.github/workflows/publish-mcp.yml).
It checks out the exact published tag, runs the repository version contract,
downloads a pinned official `mcp-publisher` release with a SHA-256 check, runs
the official `validate` command before authentication, then uses GitHub OIDC
from the protected `mcp-publish` environment for publication. No Registry
credential is stored in the repository.

The exact current manifest was accepted locally by the official
`mcp-publisher v1.8.1 validate` command and was then published through the
protected workflow. The authoritative record is queryable through the
[Official MCP Registry API](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.ECD5A%2Ftkach-security).

For future versions, the release owner must use the current official Registry
workflow rather than hand-editing registry data:

1. configure protection/review rules for the `mcp-publish` GitHub Environment;
2. verify the installable `tkach-mcp` Cargo package and its release artifact;
3. dispatch the workflow for the exact published tag, or publish a future
   GitHub Release and approve the environment gate;
4. verify the returned Registry record through the official API.

The manifest uses the current Cargo package contract and the visible
`mcp-name: io.github.ECD5A/tkach-security` marker in the crate README. Registry
registration is not turnkey hosted operation: the adapter remains a local
stdio process over an already-running loopback runtime.

The authoritative workflow and schema are maintained by the
[MCP Registry publishing guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/quickstart.mdx),
the [publisher CLI reference](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/cli/commands.md),
and the [official Registry API documentation](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md).
The Registry is currently in preview, so future publication remains a
deliberate release-owner action. No Registry credentials are stored in this
repository.

The regular version-contract CI gate also binds `server.json` to the
`tkach-mcp` Cargo package, the visible ownership marker, the loopback address,
and the required secret token shape. This is a local drift regression check;
it does not replace the official `mcp-publisher validate` gate before a
Registry publication.

## External publication status

Completed:

- all seven Rust crates at version `0.1.0` on crates.io;
- public npm publication of `tkach-security-client@0.1.0`;
- the public [v0.1.0 GitHub Release](https://github.com/ECD5A/Tkach-Security/releases/tag/v0.1.0)
  with Linux x86_64, macOS x86_64/aarch64, and Windows x86_64 archives,
  SHA-256 manifests, keyless Sigstore bundles, and GitHub attestations.
- the v0.1.0 multi-arch GHCR image, pushed with immutable release/SHA tags and
  GitHub build provenance; the package is currently private pending owner
  visibility approval;
- `tkach-mcp@0.1.0` registered as `io.github.ECD5A/tkach-security` in the
  Official MCP Registry.

Not performed yet:

- public GHCR visibility (owner action in GitHub Package Settings);
- PyPI publication, Streamable HTTP, and public gateway operation.

Public GHCR visibility requires an explicit owner action because the
repository's `GITHUB_TOKEN` cannot use the user-scoped package-visibility API
in this workflow. This runbook describes release work; it does not grant
publication authority.

### v0.1.0 Windows archive note

The v0.1.0 Windows ZIP stores valid PE binaries as `tkach` and `tkach-mcp`
without the conventional `.exe` suffix. They can be started through an explicit
path, but that does not meet the expected Windows extraction UX. The release
workflow is regression-fixed for the next release; until that release exists,
Windows users can install `tkach-cli` from crates.io instead.
