# Changelog

All notable Tkach Security changes are recorded here.

## [Unreleased]

- Preserve the `.exe` filenames in future Windows release ZIP archives, lock
  the workflow/package contract with regression tests, and smoke the actual
  native release archives before upload and signing.
- Remove the unused raster CLI-banner source; the compiled terminal banner and
  public README preview/screenshot assets remain unchanged.
- Bind MCP Registry metadata to the published Cargo adapter, visible ownership
  marker, loopback default, and secret-token contract in the regular CI gate.
- Publish and attest the v0.1.0 multi-arch GHCR image with immutable
  release/SHA tags; the package is publicly pullable after the owner-approved
  visibility change in GitHub Package Settings.
- Register `tkach-mcp@0.1.0` as `io.github.ECD5A/tkach-security` in the
  Official MCP Registry through the protected OIDC workflow.
- Harden the cross-platform real-network regression harness against the macOS
  half-close race and repeat the authorized loopback test sixteen times.
- Gate future npm and PyPI publication on a published GitHub Release and add a
  protected crates.io OIDC workflow with dependency-ordered publishing.

## [0.1.0] — 2026-09-12

- Publish the first public Tkach Security release: seven Rust crates on
  crates.io, `tkach-security-client@0.1.0` on npm, and the v0.1.0 GitHub
  Release with SHA-256 manifests, keyless Sigstore bundles, and GitHub build
  attestations for Linux, macOS, and Windows archives.
- Publish the dependency-free JavaScript/TypeScript HTTP adapter as the public
  `tkach-security-client@0.1.0` npm package and verify its four-file bundle.
- Add a tag-only OIDC npm release workflow that tests, inspects, and publishes
  future package versions automatically with provenance, while safely skipping
  versions that already exist in the registry.
- Refresh the bilingual README showcase, verification scope, contributor
  workflow, issue template, and private-repository metadata/topics without
  changing the security contract.
- Add a copyable Golden Case proving the product boundary: useful output is
  released while a compromised provider's protected-write proposal is denied
  before the executor and produces zero executor calls.
- Add copyable multi-language and MCP examples with trusted environment-only
  credentials, and make the local deterministic HTTP demo provider repeatable
  across independent requests instead of exhausting after the first smoke call.
- Add a real local `tkach serve` provider runtime with loopback-only HTTP,
  environment-only credentials, health/auth boundaries, graceful Ctrl-C
  shutdown, and a read-only fail-closed default effect profile. Keep
  `serve --demo` as the deterministic offline reference runtime.
- Make the dense Unicode block-art banner the default terminal header. Embed it
  directly in `tkach-cli` instead of loading a runtime asset; retain compact
  fallback and an explicit `TKACH_BANNER=png` path for the supplied image.
- Expand the local TUI with dedicated diagnostics, settings, and help screens,
  responsive one/two-column layout, larger spacing, status styling, eight
  keyboard-addressable actions, and the supplied Tkach PNG banner rendered as
  colored pixel cells across Windows CMD and WSL. The image path avoids
  Braille-font dependencies; `NO_COLOR` or small terminals use the compact
  header. Settings remain session-only and cannot change policy, secrets,
  endpoints, or authority.
- Replace the flat CLI screen with a compact Ratatui panel: shared TTY/pipe
  actions, retro terminal theme, selected-state contrast, status panel, and
  keyboard footer remain local and provider-independent.
- Add local `tkach doctor` diagnostics and a matching console menu entry for
  bounded readiness checks without exposing credentials or connecting a model.
- Consolidate the glossary into Architecture, remove an unused provider fixture,
  and complete source attribution for SDKs, the CLI UI module, and release tooling.
- Centralize SDK examples, validation commands, and version policy; correct
  stale SDK/UI scope statements and the installed Node package import example.
- Add local Python and Node package metadata with no runtime dependencies or
  install hooks; CI verifies wheel/npm bundle shape while public publication
  remains owner-controlled.
- Replace timestamp-sensitive release archive commands with the tested,
  source-epoch-based deterministic packaging helper and retain explicit limits
  on binary reproducibility claims.
- Make the tag preflight smoke-install both CLI and MCP binaries before a draft
  release is created.
- Keep the CLI banner inside the published `tkach-cli` crate so `cargo package`
  verifies and compiles the same embedded UI asset that source builds use.
- Add a non-root local OCI image with an explicit loopback default and bounded
  `tkach health` container check; wildcard ingress and image publication stay
  outside the current security contract.
- Add an MCP Registry draft manifest and Cargo package README with the visible
  ownership marker required for a future `tkach-mcp` publication; no registry
  login or publication is performed locally.
- Add a release version-contract gate covering all Rust crates, Python/Node
  adapters, and MCP metadata so SDK drift cannot create a mixed-version release.
- Add keyless Sigstore blob signing and exact-identity verification for release
  archives and checksum manifests before the draft GitHub Release is created.
- Add a copyable generic HTTP smoke path for `/healthz` and authenticated
  `/v1/run`, keeping the language adapters as thin carriers over that contract.
- Align the dependency license allowlist with the audited transitive `Zlib`
  license used by the terminal UI stack; advisory, source, and ban gates stay
  unchanged.
- Add safe `tkach-mcp --version`/`--help` diagnostics with strict rejection of
  undocumented arguments before credential loading.
- Make CI and release preflight package the registry-independent `tkach-core`
  crate with strict locked verification; dependent crates remain covered by
  the full workspace build/test gates until the ordered crates.io publication
  sequence makes their registry dependencies resolvable.
- Install the pinned `rustfmt` and `clippy` components explicitly for minimal
  CI toolchains, and make CLI filesystem tests reserve unique temporary
  directories atomically across Unix and Windows runners.
- Correct the public README onboarding heading and source sentence, and record
  the evidence gate that remains before MCP Registry publication.
- Add the explicit loopback-only `tkach serve --demo` reference runtime for
  bounded HTTP integration smoke tests; bearer credentials remain environment-
  supplied and the deterministic demo has no real provider or side effect.
- Expand MCP stdio regression coverage for partial/oversized framing,
  resynchronization, and static tool-failure redaction.
- Replace the terminal command prompt with arrow-key navigation, explicit path
  entry, readable results, integration guidance and the ASCII weaver emblem.
  Support immediate F1/l/L/д/Д language switching, safe terminal restoration,
  bounded UTF-8 editing, resize handling and non-interactive command compatibility.
- Prepare reproducible release artifacts, pinned CI release checks, and
  deployment diagnostics around the frozen Strong Core contract.
- Add the bounded `tkach ui` terminal dashboard with F1/`/l` language
  switching, case-insensitive English/Russian aliases, and bounded input.
- Harden the CLI adapter with true raw-terminal F1 handling, explicit language
  precedence, bounded pipe termination, terminal-safe path rendering, and
  parent-component link checks for starter initialization.
- Add the bilingual README showcase, supplied project banner, contributor
  guide, and a smaller public documentation tree with a clear public project map.
