# Security Policy

## Scope

This repository contains the Tkach Security Strong Core, bounded in-process
Gateway, and non-streaming OpenAI Responses adapter. Reports should focus on
bypasses of the documented deterministic authorization, information-flow,
data/control, provenance/classification, secret-isolation, evidence, lifecycle,
credential, parser, and egress invariants.

MCP, Anthropic, streaming, SDKs, hosted services, UI, cloud integrations,
production transport, and real executors are outside the current implementation
scope. Deployment assumptions in `PRODUCT_CONTRACT.md` remain in scope when a
bug would cross a documented Tkach boundary.

## Reporting

Please do not include real credentials or protected data in issues, tests, or
logs. Use a minimal reproduction with fake values. For a sensitive report,
contact the project owner through the repository's private security channel
when one is established.

## Development security rules

Security-critical crates forbid `unsafe_code`. Changes must include regression
tests for real security defects, pass the documented validation commands, and
avoid introducing direct privileged bypasses.
