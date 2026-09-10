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
- broker-held secrets remain outside normal model-visible structures;
- authorized broker use requires an exact `Propusk`, while raw reveal is
  denied;
- Pechat handles, receipts, errors, and debug output do not contain broker
  secret values;
- important decisions carry safe structured evidence without payload logging;
- Sled trace growth and hostile-model inputs are bounded, and the fake
  protected executor accepts only `Propusk`.
- all bounded wire collections and identifiers are rejected before unbounded
  domain allocation; malformed provenance shapes cannot create a trusted root;
- an in-progress Zaslon stream is not releasable until `finish()` returns
  `Clear`, and empty, malformed, or oversized streams deny.

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

The domain model, Krosna, Zaslon, Gnezdo, Propusk, Niti/Metka, Diode, Pechat,
Sled, and the enforcement testbed are implemented and tested. M12 adds bounded
resource budgets, conservative public metadata roots, exact secret routing,
all-operation protected external-flow gates, and explicit streaming finality.
Zaslon's canonicalizer is intentionally strict and rejects ambiguous Unicode/escape
representations; it does not detect
every semantic paraphrase. Pechat does not defend against a fully compromised
host or a deployment that separately exposes the real secret. The enforcement
testbed proves effect containment for the canonical hostile fixture; composition
scenarios A–H and tractable state-space combinations pass. The red-team pass
and Strong Core Checkpoint are complete; the repository is ready for owner
review.

The red-team pass also closed streaming-boundary, debug-redaction,
identity-spoofing, provenance-spoofing, and originless-labeling weaknesses.
M12 also closed metadata relabeling, non-export external-flow, incorrect
NetworkSend provenance, generic secret-use execution, and bounded-input gaps.
Fuzz targets cover the canonical text and domain-wire parsers; their binaries
compile on this host, while libFuzzer execution is currently unavailable under
the installed MSVC linker. Linux CI provides the bounded execution smoke test.
The official Standard Security Scan completed with 10 reviewed surfaces and no
reportable findings; its source snapshot predates M12 and that limitation is
recorded in the sealed scan scope.
