# Roadmap

This is the compact public project map. Current behavior is defined by the
Product Contract, Architecture, Security Model, and executable test suite.
Release-readiness decisions are recorded only when they become part of the
public contract or a published release.

## CURRENT

Compact public documentation tree after the Strong Core release candidate,
trusted credential-ownership hardening, v0.1 public API contract, bounded CLI
onboarding/dashboard, local HTTP adapter, thin Rust client, and MCP stdio
adapter. Productization is active by owner direction; the Core remains frozen.

## DONE

- Strong Core typed domain and canonical primitives: `Krosna`, `Propusk`,
  `Ruslo`, `Zaslon`, `Gnezdo`, `Niti`, `Metka`, `Klyuchnik`, and `Sled`.
- Provider-independent bounded Gateway with hostile-provider, composition,
  product-proof, and integration-proof coverage.
- Narrow non-streaming OpenAI Responses adapter over the existing authority
  boundary, with offline fixtures and an opt-in live guard.
- Narrow real filesystem/loopback effect boundary with explicit residuals.
- Bounded authenticated loopback runtime with lifecycle replay, cancellation,
  shutdown, safe receipts, and explicit uncertain-effect semantics.
- Zeroize-on-drop ownership for runtime authentication proof and OpenAI adapter
  configuration credentials, with redaction and compile-time regression proof.
- Local validation, dependency checks, fuzz compilation, packaging, and
  Quickstart execution are enforced by the contributor checks and CI workflow.
- v0.1 public Rust boundary contract and consumer-side API smoke test.
- Minimal `tkach` CLI with bounded `init`, strict `check`, deterministic
  `run --demo`, explicit loopback `serve --demo` reference runtime, localized
  help, local `doctor` diagnostics, and the bounded `tkach ui` dashboard,
  including no-overwrite and symlink/reparse boundary tests.
- Thin bounded tkach-client Rust adapter for the reviewed HTTP contract,
  including zeroizing token/header storage and response-framing regression
  tests.
- Separate bounded tkach-mcp stdio adapter with lifecycle negotiation, one
  explicit tkach_run tool, strict JSON-RPC limits, and no stdout diagnostics.
- Loopback-only bounded HTTP/1.1 adapter over `RuntimeService`, with strict
  `/v1/run` and static `/healthz` contracts plus transport regression tests.
- Local Python wheel and Node package metadata for the thin HTTP carriers,
  including clean-machine bundle checks without runtime dependencies or
  install hooks; external PyPI/npm publication remains deferred.
- Deterministic cross-platform release archive helper with fixed metadata,
  source-epoch inputs, checksums, and regression tests; binary reproducibility
  across toolchains remains explicitly unclaimed.

## NEXT

The current productization cycle is distribution and developer-experience
hardening: shared package metadata, release artifacts, and CI release checks
are prepared; configuration diagnostics and owner-controlled publication remain
next. It must not duplicate policy, authority, or execution logic. External
publication remains behind that contract and an owner decision.

The core remains frozen unless a concrete reproducible security or product
defect appears. Any selected phase must add adversarial regression coverage,
complete the local validation checks, update the public contract and changelog,
and end in a meaningful local commit.

## CURRENT SCOPE, NOT PERMANENT BANS

The source currently has no Streamable HTTP transport, published multi-language
SDK suite, streaming release API, generic executor, public internet gateway,
cloud control plane,
TLS/process supervisor integration, durable distributed replay, or universal
handle-relative filesystem transaction. A future boundary may be added only
if it remains a thin adapter over the existing authority model and passes its
own security review.

## PRODUCTIZATION / DISTRIBUTION / DX BOUNDARY

This phase is active after the owner-directed Strong Release candidate and
freezes the Core security contract/API. Build only thin adapters around it, in
this order:

- stable API contract (done) and minimal `tkach` CLI (done);
- language-neutral HTTP/API adapter with bounded schemas and health/diagnostic
  behavior (done for the local library boundary) plus a deterministic
  loopback-only CLI reference runtime;
- optional thin Rust/Python/JS/TS/Go adapters only after the HTTP contract is
  reviewed; the Rust client, source-level standard-library Python adapter with
  local wheel metadata, dependency-free Node runtime with TypeScript
  declarations and local package metadata, and Go module are done;
- SemVer crate/package metadata, crates.io publication, changelog, release
  notes, licensing, supply-chain and reproducible-build checks;
- signed/versioned Linux, macOS, and Windows binaries with GitHub Releases,
  OCI/Docker distribution, and CI build/test/security/release publishing;
- MCP stdio adapter (done); Streamable HTTP and, only after current
  requirements are researched and met, Official MCP Registry publication;
- production configuration, safe defaults, structured diagnostics, logging,
  health checks, integration examples, and final reliability/performance/
  security regression audit.

No item in this phase authorizes changing the frozen Core, adding
integrations for quantity, or publishing externally without an explicit owner
decision.

## READING ORDER

1. source and executable tests
2. `PRODUCT_CONTRACT.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`,
   `THREAT_MODEL.md`, and `INTEGRATION.md`
3. `DISTRIBUTION.md`, `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md`
