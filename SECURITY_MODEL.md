# Security Model

## Guarantees targeted by the Strong Core

- protected privileged actions require deterministic Tkach authorization;
- unknown privileged behavior fails closed;
- configured formal Zaslon action/content rules cannot be negotiated by model
  output, including across supported stream chunk boundaries;
- Gnezdo untrusted content remains in a data lane and cannot be deserialized or
  promoted into trusted control through a public API;
- raw action requests cannot reach the protected executor type boundary;
- kernel-issued capability grants are principal-bound and narrowed to the exact
  requested resource, even when a trusted policy matcher used a prefix;
- derived model output retains Niti lineage and the maximum parent Metka;
  model-only declassification is rejected;
- Diode treats read/export/reverse/onward edges as separate decisions and denies
  protected public export deterministically;
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

The domain model, Krosna, Zaslon, Gnezdo, Propusk, and Niti/Metka are implemented
and Diode are implemented and tested.
Zaslon's
canonicalizer is intentionally strict and rejects ambiguous Unicode/escape
representations; it does not detect every semantic paraphrase. Krosna's
deterministic rules are not a substitute for the later Gnezdo, Propusk, Niti/Metka,
Diode, Pechat, and enforcement-testbed mandates; the Strong Core checkpoint is
the only completion authority.
