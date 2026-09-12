# Contributing to Tkach Security

Thank you for helping improve Tkach Security. Tkach is a Rust security
boundary for AI agents and untrusted or compromised model output. Contributions
are welcome when they make that boundary easier to verify, harder to bypass,
or safer to integrate.

This guide describes the public contribution contract. The implementation and
tests are authoritative; the public security and product contracts are the
best starting points for understanding intended behavior.

## Before you start

Read these documents in this order:

1. [`docs/PRODUCT_CONTRACT.md`](docs/PRODUCT_CONTRACT.md) — guarantees and
   deployment conditions;
2. [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — enforceable security
   properties and non-guarantees;
3. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — implemented boundaries;
4. [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — supported integration paths;
5. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — attacker capabilities and
   expected containment.

Do not infer behavior from a branded name alone. A change is complete only
when the public contract, source, tests, and documentation agree.

## Development setup

The repository uses Rust 1.85.1 as its pinned CI toolchain and requires a
locked dependency graph. Install Rust with `rustup`, then run from the
repository root:

```text
rustup toolchain install 1.85.1 --profile minimal --no-self-update
rustup component add rustfmt --toolchain 1.85.1
rustup component add clippy --toolchain 1.85.1
cargo +1.85.1 metadata --format-version=1 --locked --no-deps
```

The normal development path is offline after dependencies have been fetched.
Do not add credentials, provider keys, or real protected data to the checkout.

## Required checks

Run the checks relevant to your change. A pull request that changes runtime,
security boundaries, dependencies, or packaging should run the complete set:

```text
cargo +1.85.1 fmt --all -- --check
cargo +1.85.1 metadata --format-version=1 --locked --no-deps
cargo +1.85.1 clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +1.85.1 test --workspace --all-targets --all-features --locked
cargo +1.85.1 test --workspace --release --all-targets --all-features --locked
cargo +1.85.1 test --workspace --doc --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo +1.85.1 doc --workspace --all-features --no-deps --locked
cargo audit
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
cargo +1.85.1 package -p tkach-core --locked
python -m unittest discover -s tools/release -p "test_*.py" -v
python -m unittest discover -s sdk/python -p "test_*.py" -v
node --test sdk/javascript/test_tkach_client.mjs
(cd sdk/go && go test ./... && go vet ./...)
```

For a focused change, state exactly which checks were run and why any check
was not applicable. Do not report a check as passing when it was skipped,
inconclusive, or unavailable.

Documentation-only changes (`.md`, `.mdx`, `.rst`, `.adoc`, `.txt`, `docs/`,
`LICENSE`, and `assets/`) are intentionally excluded from the GitHub CI trigger
so wording and artwork updates stay fast. Any change to source, manifests,
configuration, workflows, fixtures, or release tooling still runs the code and
security gates.

The onboarding and adapter paths should also remain usable:

```text
cargo run -p tkach-gateway --example quickstart --locked
cargo run -p tkach-cli -- --help
cargo run -p tkach-cli -- run --demo
```

## Security-sensitive changes

Treat every model response, tool result, document, MCP message, provider
field, and caller-supplied request as hostile data unless the existing typed
boundary explicitly proves otherwise.

Security-sensitive changes must:

- preserve default-deny behavior and deterministic authorization in Krosna;
- keep model output in DATA and prevent it from minting control, authority,
  `Propusk`, executor, broker, or release values;
- preserve exact scope, principal binding, provenance, classification, and
  directional flow checks;
- keep raw secrets out of model-visible data, logs, errors, evidence, tests,
  fixtures, and examples;
- retain bounded parsing, collection sizes, lifecycle state, framing, and
  terminal failure semantics;
- avoid adding network access, retries, dynamic code execution, or privileged
  bypasses without an explicit boundary design and review;
- include a regression test for every demonstrated security defect or bypass;
- include adversarial tests for malformed, ambiguous, replayed, over-limit,
  cancelled, and terminal inputs when those cases are relevant;
- update the applicable public contract, threat model, evidence, and
  changelog entries.

The Core is treated as a stable boundary. Change it only for a demonstrated
security or product defect, and explain the invariant that the change
strengthens. CLI, HTTP, MCP, client, and future SDK work belongs in adapters;
do not duplicate authorization or security logic outside the Core.

Do not use real credentials, private customer data, undisclosed vulnerability
details, or live provider access in tests. Use deterministic fixtures and fake
values. For a suspected vulnerability, follow [`SECURITY.md`](SECURITY.md)
instead of opening a public issue with exploit details.

## Tests and evidence

Tests should prove behavior at the narrowest boundary that owns the invariant.
Prefer a small regression test plus an independent hostile case over a broad
test that only exercises a happy path. Keep security claims proportional to
the evidence: an offline proof does not establish deployment TLS, process
isolation, hosted-service behavior, or protection from a caller that bypasses
the Tkach boundary.

When behavior or coverage changes, update the applicable public contract and
the changelog with the command, result, scope, and remaining limitation. Keep
generated build output and local scan files out of the repository.

## Documentation and public claims

Documentation must describe the current implementation, not an intended future
integration. Clearly label partial, local-only, opt-in, unavailable, or
unverified features. In particular, do not claim that crates.io publication,
prebuilt binaries, an OCI image, a hosted gateway, or a published multi-language SDK package,
MCP Registry registration exists until the corresponding release owner has
actually completed and verified it.

Keep maintainer-only engineering notes, local tool state, temporary scan
configuration, and unpublished release records out of public docs. Public
contributors should use the checked-in contracts listed above.

## Commit and pull request expectations

Keep commits small, focused, and easy to review. A useful commit message says
what boundary changed and why, for example:

```text
gateway: reject replayed lifecycle frames before dispatch
```

Each pull request should include:

- a concise problem statement and the affected boundary;
- the security invariant or product behavior being preserved or added;
- tests and checks run, including any limitations or unavailable tooling;
- documentation and changelog updates when the public behavior changes;
- notes about compatibility, dependency, performance, and residual risks;
- no unrelated formatting churn or generated files.

Reviewers may request a smaller patch when a change mixes refactoring with a
security decision. Keep security decisions explicit and reviewable.

Contributors should not push directly to protected branches, create public
releases, publish packages, register integrations, or make production-support
claims from a pull request. Release tags, package publication, attestations,
registry submissions, and release notes are maintainer-owned actions after the
release gates pass.

## Local files that must stay local

Never add these categories to a commit:

- build output such as `target/` or `fuzz/target/`;
- temporary directories or files, including literal `%TEMP%/` output;
- local engineering material, tool state, or unpublished release records;
- `.env` files, API keys, tokens, private keys, certificates, dumps, or logs
  containing sensitive data.

Check the staged file list before submitting:

```text
git diff --cached --name-status
git status --short --ignored
```

## License

By contributing, you agree that your contribution is provided under the
repository's [Apache License 2.0](LICENSE).

Keep the concise Tkach Security / Copyright 2026 ECD5A / Apache-2.0 header
in first-party runtime modules, SDK entry points and declarations, and release
tooling. Follow the existing source header and preserve its repository, LICENSE,
and SECURITY.md references. Do not add banners to JSON, lockfiles, fixtures,
artwork, or every documentation page.
