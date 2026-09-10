# Roadmap

This is the compact project map. The permanent rules live in the root
constitution; current behavior is summarized in `CURRENT_BASELINE.md`; test
and security evidence is in `EVIDENCE.md`.

## CURRENT

Compact documentation tree after the local `production-runtime-v0.1` baseline,
trusted credential-ownership hardening, Strong Core checkpoint, v0.1 public API
contract, bounded CLI onboarding adapter, local HTTP adapter, thin Rust client,
and MCP stdio adapter. Productization is now active by owner direction; the
Core remains frozen.

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
  Quickstart execution documented in `EVIDENCE.md`.
- v0.1 public Rust boundary contract and consumer-side API smoke test.
- Minimal `tkach` CLI with bounded `init`, strict `check`, and deterministic
  `run --demo` onboarding path, including no-overwrite and symlink/reparse
  boundary tests.
- Thin bounded tkach-client Rust adapter for the reviewed HTTP contract,
  including zeroizing token/header storage and response-framing regression
  tests.
- Separate bounded tkach-mcp stdio adapter with lifecycle negotiation, one
  explicit tkach_run tool, strict JSON-RPC limits, and no stdout diagnostics.
- Loopback-only bounded HTTP/1.1 adapter over `RuntimeService`, with strict
  `/v1/run` and static `/healthz` contracts plus transport regression tests.

## NEXT

The current productization cycle is distribution and developer-experience
hardening: shared package metadata, release artifacts, and CI release checks
are prepared; configuration diagnostics and owner-controlled publication remain
next. It must not duplicate policy, authority, or execution logic. External
publication remains behind that contract and an owner decision.

The core remains frozen unless a concrete reproducible security or product
defect appears. Any selected phase must add adversarial regression coverage,
complete the local validation matrix, update `CURRENT_BASELINE.md` and
`EVIDENCE.md`, and end in a meaningful local commit.

## CURRENT SCOPE, NOT PERMANENT BANS

The source currently has no Streamable HTTP transport, multi-language SDK,
streaming release API, generic executor, public internet gateway, UI, cloud
control plane,
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
  behavior (done for the local library boundary);
- optional thin Rust/Python/JS/TS/Go adapters only after the HTTP contract is
  reviewed; the first Rust client is done;
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

1. `../Tkach Security — MASTER_MANDATE.md`
2. `CURRENT_BASELINE.md`
3. source and executable tests
4. `PRODUCT_CONTRACT.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`,
   `THREAT_MODEL.md`, and `INTEGRATION.md`
5. `EVIDENCE.md` and `DEVELOPMENT.md`
