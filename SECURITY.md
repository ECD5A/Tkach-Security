# Security Policy

## Scope

This repository contains the Tkach Security Strong Core, bounded Gateway,
narrow real local-effect boundary, non-streaming OpenAI Responses adapter, and
thin local CLI, HTTP, Rust client, and MCP stdio adapters.
Reports should target bypasses of deterministic authorization, information
flow, DATA/CONTROL separation, provenance/classification, secret isolation,
payload-free evidence, lifecycle, parser, credential, or egress invariants.

The current source has no multi-language SDK, Streamable HTTP adapter,
Anthropic adapter, streaming release API, hosted service, UI, cloud control
plane, or public internet gateway. Deployment assumptions in [the product
contract](docs/PRODUCT_CONTRACT.md) remain in scope when a defect crosses a
documented Tkach boundary.

## Reporting

Do not include real credentials or protected data in issues, tests, or logs.
Use fake values and a minimal reproduction. For a sensitive report, contact
the project owner through the repository's private security channel when one
is established.

## Development security rules

Security-critical crates forbid `unsafe_code`. Changes must include regression
tests for real security defects, pass the validation matrix in
[the evidence record](docs/EVIDENCE.md), and avoid direct privileged bypasses.
