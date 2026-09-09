# Security Model

## Guarantees targeted by the Strong Core

- protected privileged actions require deterministic Tkach authorization;
- unknown privileged behavior fails closed;
- untrusted data cannot mint authority, capabilities, or policy changes;
- provenance and conservative protected classification are retained through
  controlled transformations;
- information-flow decisions are directional and separate read from export;
- broker-held secrets remain outside normal model-visible structures;
- important decisions carry safe structured evidence without payload logging.

These guarantees apply only to validated inputs reaching the core and to
executors that do not provide an out-of-band bypass.

## Assumptions

- the host process and operating system are not fully compromised;
- external adapters correctly map and validate inputs into the domain types;
- protected executors require the kernel-issued authorization type;
- real secrets are not separately inserted into model-visible context.

## Non-guarantees

The core does not solve prompt injection, semantic intent detection, arbitrary
LLM compromise, perfect taint analysis, or all possible data leakage. It does
not protect a deployment that gives the model a direct privileged path or a
fully compromised operating system.

## Current implementation status

This baseline is scaffolding only. See `ROADMAP.md` for the active mandate;
claims above describe the intended Strong Core contract and must not be read as
completed guarantees until executable tests and the checkpoint say so.

