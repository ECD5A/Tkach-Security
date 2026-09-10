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
- Sled request metadata is projected to payload-free principal, operation,
  capability, provenance, and destination categories; arbitrary request labels
  do not become diagnostic output.
- Sled evidence, execution receipts, and broker receipts are output artifacts,
  not deserializable authority inputs; only kernel code records decisions.
- Zaslon pattern memory has an aggregate budget and streaming matching uses
  incremental bounded state rather than copying a rule-sized suffix per chunk.
- Pechat's fake broker has both per-secret and aggregate secret-byte budgets.
- all bounded wire collections and identifiers are validated against fixed
  limits, and malformed provenance shapes cannot create a trusted root; input
  adapters must impose reader/token byte limits before generic deserializers
  materialize hostile oversized strings;
- an in-progress Zaslon stream is not releasable until `finish()` returns
  `Clear`, and a finished stream is terminal: later input fails closed;
  empty, malformed, or oversized streams deny.
- the Phase 1 gateway bounds raw requests, messages, metadata, tool labels,
  provider chunks, cumulative staged output, model context, tool results,
  action proposals, and provider turns before release or protected effects;
- external messages are contained by Gnezdo and ingress Zaslon before provider
  invocation, while client tool declarations remain data and cannot extend the
  fixed trusted tool catalog;
- provider output can propose only text and typed ActionRequest values; it
  cannot construct or receive Decision, Propusk, trusted provenance,
  declassification authority, executor, or broker values;
- provider output is buffered until final Krosna/Diode and egress Zaslon checks
  pass, and final output validation occurs before any action in that response
  executes;
- protected action proposals are preflighted through Krosna before execution,
  AwaitToolResults permits read-only actions only, and a repeated action in one
  lifecycle is rejected as a replay;
- Phase 1 fake tools accept only Propusk, preserve Niti/Metka on data results,
  keep broker-held raw material private, and expose only payload-free effect
  receipts;
- malformed, timeout, failure, cancellation, over-limit, denied, and invalid
  release-destination provider paths fail closed without returning staged
  output or executing staged actions.
- the OpenAI adapter keeps credentials in trusted configuration, rejects
  ambiguous endpoints, disables redirects, bounds HTTP bodies, and maps
  transport failures to payload-free provider errors;
- the OpenAI wire boundary rejects unknown response item kinds, duplicate
  fields, incomplete responses, malformed function calls, oversized values,
  and non-empty tool arguments;
- OpenAI response/call IDs are bounded replay markers and read-only tool
  results are paired into explicit `function_call_output` DATA items; neither
  ID metadata nor provider claims are authority;
- the OpenAI adapter explicitly disables provider persistence/background mode
  and does not expose built-in provider tools or MCP capabilities.

These guarantees apply only to validated inputs reaching the core and to
executors that do not provide an out-of-band bypass.

## Assumptions

- the host process and operating system are not fully compromised;
- external adapters correctly map and validate inputs into the domain types;
- protected executors require the kernel-issued authorization type;
- real secrets are not separately inserted into model-visible context;
- the Gateway's trusted constructor inputs (Krosna, Zaslon instances, release
  destination, and executor implementation) are supplied by trusted host code;
  the host must not give the provider an out-of-band executor or broker path;
- Phase 1 fake tools are deterministic test doubles, not production transport
  or transaction semantics; a real executor must preserve the Propusk-only
  boundary and bounded result contract;
- `Serialize` on model-readable data is context construction, not an egress
  authorization decision; adapters must apply Diode/Zaslon before release.

## Non-guarantees

The core does not solve prompt injection, semantic intent detection, arbitrary
LLM compromise, perfect taint analysis, or all possible data leakage. It does
not protect a deployment that gives the model a direct privileged path or a
fully compromised operating system. Policy `RuleId` values are trusted,
validated configuration labels and remain in evidence for explainability;
adapters must not treat them as attacker data. Pechat intentionally exposes
opaque handle labels and an authorized caller can distinguish a successful
broker use from an unknown handle; this is metadata, not a raw-secret leak,
and this review does not claim constant-time behavior.

## Current implementation status

The domain model, Krosna, Zaslon, Gnezdo, Propusk, Niti/Metka, Diode, Pechat,
Sled, the enforcement testbed, and the provider-independent Gateway Phase 1
boundary are implemented and tested. The first real-provider milestone adds a
non-streaming OpenAI Responses adapter with an offline fake transport, strict
wire fixtures, an actual Gateway integration test, and an opt-in live smoke
test that is skipped unless explicitly enabled. Strong Core
Hardening Round 3 additionally closes diagnostic metadata injection and
forgeable evidence construction, fixes Niti wire round-trips, rejects unknown
declassification resources, bounds aggregate Pechat memory, and replaces the
quadratic streaming matcher state with incremental matching.
Zaslon's canonicalizer is intentionally strict and rejects ambiguous Unicode/
escape representations; it does not detect every semantic paraphrase. Pechat
does not defend against a fully compromised
host or a deployment that separately exposes the real secret. The enforcement
testbed proves effect containment for the canonical hostile fixture; composition
scenarios A–H and tractable state-space combinations pass. The red-team pass
and the final adversarial hardening checkpoint is complete only after the
validation matrix and freeze commit recorded in `DEVELOPMENT.md`; provider
streaming, MCP, SDK, cloud, UI, and production gateway orchestration are not
part of this status. The OpenAI adapter's HTTPS transport is a bounded
provider boundary, not a production gateway or deployment integration.

Public `UntrustedContent` and `TaggedData<T>` serialization remains
intentionally model-context serialization: it does not mint authority or
bypass the core, but release adapters must enforce the egress boundary
separately.

The red-team pass also closed streaming-boundary, debug-redaction,
identity-spoofing, provenance-spoofing, and originless-labeling weaknesses.
Hardening Round 2 also closed model-write source confusion, generic
SecretBroker executor execution, post-finish stream extension, and oracle gaps
at exact bounded-string and capability-operation boundaries.
Fuzz targets cover the canonical text, domain-wire, gateway-wire, and OpenAI
Responses parsers; their binaries compile on this host, while libFuzzer
execution is currently unavailable under the installed MSVC linker. Linux CI
provides the bounded execution smoke test.
The Round 2 scan remains historical and incomplete. Round 3's Standard Security
Scan is tracked separately in the workbench; if it is not sealed before the
freeze, the final report records that limitation rather than calling it PASS.
Local security review, mutation testing, independent oracles, dependency
checks, and the full validation gate are reported with their exact results.
