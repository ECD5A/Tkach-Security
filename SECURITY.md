# Security Policy

## Scope

This repository is currently the provider-independent Tkach Security Strong
Core. Reports should focus on bypasses of its documented deterministic
authorization, information-flow, data/control, provenance/classification,
secret-isolation, and evidence invariants.

Provider integrations, hosted services, UI, and deployment configuration are
not part of the current scope.

## Reporting

Please do not include real credentials or protected data in issues, tests, or
logs. Use a minimal reproduction with fake values. For a sensitive report,
contact the project owner through the repository's private security channel
when one is established.

## Development security rules

Security-critical crates forbid `unsafe_code`. Changes must include regression
tests for real security defects, pass the documented validation commands, and
avoid introducing direct privileged bypasses.

