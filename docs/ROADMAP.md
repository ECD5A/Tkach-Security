# Roadmap

This is the compact project map. The permanent rules live in the root
constitution; current behavior is summarized in `CURRENT_BASELINE.md`; test
and security evidence is in `EVIDENCE.md`.

## CURRENT

Compact documentation tree after the local `production-runtime-v0.1` baseline,
trusted credential-ownership hardening, Strong Core checkpoint, and v0.1 public
API contract. The runtime source is stable; the next product decision is not
assumed.

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

## NEXT

Choose one boundary only from demonstrated risk and useful workload evidence:

1. reviewed authenticated IPC/process deployment;
2. durable replay and effect recovery semantics; or
3. another thin adapter over the existing Gateway/core authority path.

The core remains frozen unless a concrete reproducible security or product
defect appears. Any selected phase must add adversarial regression coverage,
complete the local validation matrix, update `CURRENT_BASELINE.md` and
`EVIDENCE.md`, and end in a meaningful local commit.

## CURRENT SCOPE, NOT PERMANENT BANS

The source currently has no MCP adapter, provider SDK, streaming release API,
generic executor, public internet gateway, UI, cloud control plane,
TLS/process supervisor integration, durable distributed replay, or universal
handle-relative filesystem transaction. A future boundary may be added only
if it remains a thin adapter over the existing authority model and passes its
own security review.

## RESERVED NEXT PHASE — PRODUCTIZATION / DISTRIBUTION / DX

This phase is intentionally inactive until Strong Release is accepted. Then
freeze the Core security contract/API and build only thin adapters around it:

- SemVer crate/package metadata, crates.io publication, changelog, release
  notes, licensing, supply-chain and reproducible-build checks;
- a minimal `tkach` CLI (`init`, check, run), copyable examples, README
  Quick Start under five minutes, and clean-machine onboarding proof;
- signed/versioned Linux, macOS, and Windows binaries with GitHub Releases,
  OCI/Docker distribution, and CI build/test/security/release publishing;
- a language-neutral local HTTP/API gateway plus optional thin Rust/Python/
  JS/TS/Go adapters, with no duplicated security/business logic;
- a separate MCP server/adapter and, only after current requirements are
  researched and met, Official MCP Registry publication;
- production configuration, safe defaults, structured diagnostics, logging,
  health checks, integration examples, and final reliability/performance/
  security regression audit.

No item in this reserved phase authorizes changing the frozen Core, adding
integrations for quantity, or publishing externally without an explicit owner
decision.

## READING ORDER

1. `../Tkach Security — MASTER_MANDATE.md`
2. `CURRENT_BASELINE.md`
3. source and executable tests
4. `PRODUCT_CONTRACT.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`,
   `THREAT_MODEL.md`, and `INTEGRATION.md`
5. `EVIDENCE.md` and `DEVELOPMENT.md`
