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
- untrusted contexts cannot spoof a trusted principal, and public wire values
  cannot inject trusted `System` provenance;
- provenance and conservative protected classification are retained through
  controlled transformations;
- originless derivations are labeled `Unknown`, never laundered to `Public`;
- information-flow decisions are directional and separate read from export;
- model-controlled writes, executes, declassification requests, and policy
  effects are evaluated as model-originated flow edges, not resource-originated
  reads;
- broker-held secrets remain outside normal model-visible structures;
- authorized broker use requires an exact `Propusk`, while raw reveal is
  denied;
- a direct protected-executor call addressed to `SecretBroker` is rejected;
- Pechat handles, receipts, errors, and debug output do not contain broker
  secret values;
- important decisions carry safe structured evidence without payload logging;
- Sled trace growth and hostile-model inputs are bounded, and the fake
  protected executor accepts only `Propusk`.
- all bounded wire collections and identifiers are rejected before unbounded
  domain allocation; malformed provenance shapes cannot create a trusted root;
- an in-progress Zaslon stream is not releasable until `finish()` returns
  `Clear`, and a finished stream is terminal: later input fails closed;
  empty, malformed, or oversized streams deny.

These guarantees apply only to validated inputs reaching the core and to
executors that do not provide an out-of-band bypass.

## Assumptions

- the host process and operating system are not fully compromised;
- external adapters correctly map and validate inputs into the domain types;
- protected executors require the kernel-issued authorization type;
- real secrets are not separately inserted into model-visible context;
- `Serialize` on model-readable data is context construction, not an egress
  authorization decision; adapters must apply Diode/Zaslon before release.

## Non-guarantees

The core does not solve prompt injection, semantic intent detection, arbitrary
LLM compromise, perfect taint analysis, or all possible data leakage. It does
not protect a deployment that gives the model a direct privileged path or a
fully compromised operating system. Bounded Sled evidence contains typed,
attacker-influenced identifiers required for diagnosis; it contains no raw
payload, but exposing traces to a hostile model can still create a metadata
side channel.

## Current implementation status

The domain model, Krosna, Zaslon, Gnezdo, Propusk, Niti/Metka, Diode, Pechat,
Sled, and the enforcement testbed are implemented and tested. Strong Core
Hardening Round 2 adds model-origin flow-source enforcement for non-read
effects, direct SecretBroker executor defense in depth, terminal stream state,
and independent truth-table/oracle tests for authority, lane, scope,
classification, direction, secret handles, unknown states, and public APIs.
Zaslon's canonicalizer is intentionally strict and rejects ambiguous Unicode/
escape representations; it does not detect every semantic paraphrase. Pechat
does not defend against a fully compromised
host or a deployment that separately exposes the real secret. The enforcement
testbed proves effect containment for the canonical hostile fixture; composition
scenarios A–H and tractable state-space combinations pass. The red-team pass
and Strong Core Checkpoint are complete; the repository is ready for owner
review.

Public `UntrustedContent` and `TaggedData<T>` serialization remains
intentionally model-context serialization: it does not mint authority or
bypass the core, but release adapters must enforce the egress boundary
separately.

The red-team pass also closed streaming-boundary, debug-redaction,
identity-spoofing, provenance-spoofing, and originless-labeling weaknesses.
Hardening Round 2 also closed model-write source confusion, generic
SecretBroker executor execution, post-finish stream extension, and oracle gaps
at exact bounded-string and capability-operation boundaries.
Fuzz targets cover the canonical text and domain-wire parsers; their binaries
compile on this host, while libFuzzer execution is currently unavailable under
the installed MSVC linker. Linux CI provides the bounded execution smoke test.
The Round 2 Standard Security Scan is running under scan id
`9f1895db-2b61-466c-b1c2-fb898567643e`; at the last check it remained in
preflight with zero findings and is not treated as a completed report. Local
security review, mutation testing, independent oracles, dependency checks, and
the full validation gate are the authoritative evidence for this checkpoint.
