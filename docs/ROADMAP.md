# Roadmap

Current behavior is defined by the [product contract](PRODUCT_CONTRACT.md),
[architecture](ARCHITECTURE.md), [security model](SECURITY_MODEL.md), and
executable tests. This page tracks direction, not a second release checklist.

## Current release

Public **v0.1.2** completes the first coordinated hardening release. Installation
channels are listed in the [README](../README.md#packages-and-downloads--v012);
[release notes](releases/v0.1.2.md) record checks and limitations.

The Core security contract remains frozen. A change needs a reproducible
security or product defect; new integrations must stay thin and must not
duplicate policy, authority, or execution logic.

The published `v0.1.2` artifacts include the adapter/runtime hardening that
aligns bounded client deadlines, adds slow-response coverage, and separates
liveness from replay-capacity admission readiness. CI also executes the
protected-effect Golden Case on every supported platform and runs bounded fuzz
smoke after all targets are built.

## Delivered

- **Security Core:** typed `Krosna`, `Propusk`, `Ruslo`, `Zaslon`, `Gnezdo`,
  `Niti`, `Metka`, `Klyuchnik`, and `Sled`; v0.1 public Rust API and
  consumer-side API smoke coverage.
- **Gateway and runtime:** bounded provider-independent orchestration,
  filesystem/loopback effects with explicit residuals, replay/cancellation/
  shutdown handling, uncertain-effect semantics, and bounded payload-free
  receipts. Runtime authentication and provider credentials have
  zeroize-on-drop ownership and redaction coverage.
- **Local operation:** CLI onboarding, strict request validation, offline demo,
  bilingual interactive panel, diagnostics, auth and health checks, and a
  real loopback provider runtime with a read-only default effect profile.
  The optional OpenAI Responses adapter is non-streaming, with offline
  fixtures and an opt-in live guard.
- **Integration:** bounded HTTP/1.1 `/v1/run`, `/healthz`, and `/readyz`, thin Rust,
  Python, JavaScript/TypeScript and Go clients, and a separate MCP stdio
  adapter with one `tkach_run` tool. Python and Node packages have no runtime
  dependencies or install hooks; Go remains a source-level module.
- **Distribution:** seven Rust crates, npm and PyPI clients, signed/attested
  Linux/macOS/Windows archives, public Linux amd64/arm64 OCI image, and
  Official MCP Registry registration, all at `0.1.2`. Publishing workflows
  use OIDC and reviewed GitHub environments.
- **Verification and examples:** hostile-provider, composition and integration
  coverage; transport and filesystem boundary regressions; contributor/CI
  checks; isolated install checks; copyable multi-language examples and the
  offline Golden Case. Archive metadata is deterministic for identical
  inputs; cross-toolchain binary reproducibility is not claimed.

## Next priorities

Improve onboarding and deployment documentation from reproducible user
feedback; fix demonstrated defects before adding integrations. Each selected
code change needs adversarial regression coverage, the applicable contributor
checks, updated contract/changelog, and a meaningful commit.

Structured logging, public TLS/service operation, process supervision, and
additional transports need separately scoped deployment work and review.
They are not implied by registry publication or the current local profile.

## Outside the current contract

Streamable HTTP, a streaming release API, a generic executor, a public internet
gateway, a cloud control plane, durable distributed replay, and universal
handle-relative filesystem transactions are not implemented. A future
boundary must preserve the authority model and pass its own security review.

Follow the [threat model](THREAT_MODEL.md) for assumptions and residual risks,
[distribution runbook](DISTRIBUTION.md) for future releases, and
[contributor guide](../CONTRIBUTING.md) for checks. Publication and changes to
external visibility still require an explicit owner decision.
