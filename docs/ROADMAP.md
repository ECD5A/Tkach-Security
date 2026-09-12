# Roadmap

This is the compact public project map. Current behavior is defined by the
Product Contract, Architecture, Security Model, and executable test suite.
Release-readiness decisions are recorded only when they become part of the
public contract or a published release.

## CURRENT

Public v0.1.1 is released after Strong Core hardening, the v0.1 API contract,
bounded CLI onboarding/dashboard, local HTTP adapter, thin Rust client, and
MCP stdio adapter. The local authenticated provider runtime has a read-only
default profile. Copyable multi-language examples and the Golden Case are part
of the public showcase. Productization now focuses on onboarding, deployment
boundaries, and release quality; the Core remains frozen.

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
  help, local `doctor` diagnostics, bounded `tkach ui` dashboard, and a real
  loopback `serve` provider runtime with environment-only credentials, health,
  auth, graceful stop, and a fail-closed read-only effect profile, including
  no-overwrite and symlink/reparse boundary tests.
- Thin bounded tkach-client Rust adapter for the reviewed HTTP contract,
  including zeroizing token/header storage and response-framing regression
  tests.
- Separate bounded tkach-mcp stdio adapter with lifecycle negotiation, one
  explicit tkach_run tool, strict JSON-RPC limits, and no stdout diagnostics.
- Loopback-only bounded HTTP/1.1 adapter over `RuntimeService`, with strict
  `/v1/run` and static `/healthz` contracts plus transport regression tests.
- Local Python wheel and Node package metadata for the thin HTTP carriers,
  including clean-machine bundle checks without runtime dependencies or
  install hooks; the thin Node adapter is published as
  `tkach-security-client@0.1.1` on npm and PyPI; all seven Rust crates are
  published at `0.1.1`.
- Deterministic cross-platform release archive helper with fixed metadata,
  source-epoch inputs, checksums, and regression tests; binary reproducibility
  across toolchains remains explicitly unclaimed.
- Copyable Rust/HTTP/Python/JavaScript/Go/MCP examples and an offline Golden
  Case that releases useful output while denying a compromised provider's
  protected-write proposal before executor invocation.
- Clean-install checks for isolated CLI/MCP binaries and Python/Node package
  bundles; these prove package shape in addition to the published v0.1.0
  Rust/npm artifacts.

## NEXT

The v0.1.1 distribution cycle is complete: shared package metadata, hosted
cross-platform verification, examples, Golden Case, crates.io, npm, PyPI,
multi-arch OCI, MCP Registry, and signed GitHub archives are live. The release
closes the macOS network-test race and protects package publication with OIDC
and reviewed GitHub environments. Its evidence record is in
[`docs/releases/v0.1.1.md`](releases/v0.1.1.md). Future work must remain a thin
adapter or an independently justified hardening change; it must not duplicate
policy, authority, or execution logic.

The core remains frozen unless a concrete reproducible security or product
defect appears. Any selected phase must add adversarial regression coverage,
complete the local validation checks, update the public contract and changelog,
and end in a meaningful local commit.

## CURRENT SCOPE, NOT PERMANENT BANS

The source currently has no Streamable HTTP transport, published Go SDK,
streaming release API, generic executor, public
internet gateway, or cloud control plane,
TLS/process supervisor integration, durable distributed replay, or universal
handle-relative filesystem transaction. A future boundary may be added only
if it remains a thin adapter over the existing authority model and passes its
own security review.

## PRODUCTIZATION / DISTRIBUTION / DX BOUNDARY

This phase is active after the owner-directed Strong Core release and
freezes the Core security contract/API. Build only thin adapters around it, in
this order:

- stable API contract (done) and minimal `tkach` CLI (done);
- language-neutral HTTP/API adapter with bounded schemas and health/diagnostic
  behavior (done for the local library boundary), a deterministic loopback
  reference runtime, and a local provider runtime with a reviewed read-only
  default profile;
- optional thin Rust/Python/JS/TS/Go adapters only after the HTTP contract is
  reviewed; the Rust client, published standard-library Python adapter,
  dependency-free published Node runtime with TypeScript declarations, and Go
  module are done;
- SemVer crate/package metadata, crates.io publication, changelog, release
  notes, licensing, supply-chain and reproducible-build checks (the seven
  `0.1.1` crates, npm/PyPI adapters, and signed GitHub archives are published;
  the v0.1.1 GHCR image is built, pushed, attested, and public);
- signed/versioned Linux, macOS, and Windows binaries with GitHub Releases,
  OCI/Docker distribution, and CI build/test/security/release publishing
  (GitHub Release v0.1.1 is published; the multi-arch GHCR image is pushed,
  attested, and publicly pullable);
- MCP stdio adapter (done); Streamable HTTP and, only after current
  requirements are researched and met, Official MCP Registry publication
  (adapter, public package, manifest, and active Registry registration are
  done; Streamable HTTP remains intentionally out of scope);
- release automation for `v0.1.1` is operational: npm/PyPI publish only after
  a published GitHub Release, and crates.io publication is a protected,
  manually approved dependency-ordered gate;
- production configuration, safe defaults, diagnostics and health checks are
  done for the local profile; structured logging, public TLS/service operation,
  and process supervision remain separate deployment work. Integration
  examples and the v0.1.1 release review are done.

No item in this phase authorizes changing the frozen Core, adding
integrations for quantity, or publishing externally without an explicit owner
decision.

## READING ORDER

1. source and executable tests
2. `PRODUCT_CONTRACT.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`,
   `THREAT_MODEL.md`, and `INTEGRATION.md`
3. `DISTRIBUTION.md`, `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md`
