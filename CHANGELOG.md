# Changelog

All notable Tkach Security changes are recorded here. The `0.1.0` entry is a
release candidate description, not a claim that a public release exists.

## [Unreleased]

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
- Add safe `tkach-mcp --version`/`--help` diagnostics with strict rejection of
  undocumented arguments before credential loading.
- Make CI and release preflight compile every packaged crate with strict
  `cargo package --workspace --locked` verification instead of skipping the
  package build step.
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

## [0.1.0] — release candidate, not published

- Freeze the provider-independent Strong Core and bounded Gateway authority
  boundary.
- Add the reviewed local CLI, loopback HTTP adapter, bounded Rust client, and
  MCP stdio adapter.
- Preserve fail-closed authorization, bounded framing, safe receipts, and
  credential redaction/zeroization evidence across the adapter layers.
