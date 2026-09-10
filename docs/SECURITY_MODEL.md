# Security Model

This document states the current enforceable security properties. It separates
guarantees from assumptions, non-guarantees, and evidence. The product
contract is the shorter integrator-facing version.

## Guarantees

- Krosna is the deterministic authorization point. Unknown, malformed,
  conflicting, or unmatched privileged state fails closed.
- Zaslon's canonical hard-deny rules and terminal streaming decisions cannot be
  negotiated by model output or bypassed at supported chunk boundaries.
- Gnezdo keeps external content in DATA. Public APIs cannot promote it into
  trusted CONTROL; untrusted contexts cannot spoof principal or provenance.
- A raw `ActionRequest` is not execution authority. Only a kernel-issued,
  principal-bound, exact-scope `Propusk` reaches `ProtectedExecutor`.
- Ruslo treats READ, EXPORT, TRANSFER, and reverse direction as separate
  decisions. Protected-derived public export is denied unless the trusted flow
  and classification contract explicitly permits it.
- Niti lineage and Metka classification survive supported derivations and
  tool-result handoffs. Joins are conservative; model-only declassification is
  rejected and originless derivation becomes `Unknown`.
- Klyuchnik keeps broker-held values outside model-visible structures. Secret
  use requires an exact Propusk route; raw reveal is denied; handles, receipts,
  errors, debug, and Sled do not contain raw values. Owned broker bytes are
  zeroized on drop.
- Sled is bounded, structured, payload-free evidence and never an authority
  input. Request metadata is projected to safe categories.
- Gateway and provider boundaries bound raw bytes, collections, model context,
  staged output, actions, turns, responses, IDs, replay state, and receipts
  before protected work or release. Provider output remains hostile DATA and
  cannot construct policy, authority, executor, broker, or release values.
- Final output is buffered until Krosna/Ruslo/Zaslon gates pass. Malformed,
  over-limit, denied, failed, cancelled, replayed, or uncertain lifecycles do
  not release staged output or silently retry an effect.
- Runtime authentication occurs before Gateway admission, but identifies a
  caller only; it does not authorize model actions. The trusted stored proof is
  private, bounded, redacted, and zeroized when `RuntimeAuthenticator` drops.
  Caller-owned frame buffers and host memory are outside that guarantee.
- The runtime listener is loopback-only, length-prefixed, sequential, and
  bounded. Shutdown, cancellation, `FAILED_BEFORE_EFFECT`, and
  `OUTCOME_UNKNOWN` are explicit terminal states.
- The OpenAI adapter keeps its credential in trusted configuration, validates
  its HTTPS endpoint, zeroizes the configuration-owned credential on drop,
  disables redirects, bounds response bodies, rejects ambiguous/unknown wire
  forms, and maps only fixed provider function names to raw proposals. HTTP
  client/header copies and caller-owned buffers are outside this guarantee.

These guarantees apply only to validated inputs reaching the boundary and to
integrations that do not provide an out-of-band executor, broker, release, or
raw-credential path.

## Primitive roles and necessity

| Primitive | Security role | What fails if removed |
| --- | --- | --- |
| Krosna | deterministic policy and Propusk issuer | proposals can become authority |
| Propusk | exact typed execution capability | raw requests can reach effects |
| Ruslo | directional information-flow control | READ can be confused with EXPORT |
| Zaslon | formal content/action hard deny | representation or chunk seams can bypass a deny |
| Gnezdo | DATA/CONTROL containment | instructions can impersonate control |
| Niti | bounded provenance lineage | protected origin can disappear |
| Metka | monotonic sensitivity classification | protected data can be relabeled public |
| Klyuchnik | broker-side secret-use isolation | raw credentials can enter model context |
| Sled | safe bounded decision evidence | diagnosis requires unsafe payload logging |

The nine names are not nine competing policy engines. Krosna authorizes,
Ruslo controls flow, Zaslon blocks formal content/action, Gnezdo/Niti/Metka
carry security state, Propusk gates execution, Klyuchnik gates secrets, and
Sled records safe evidence. Gateway owns lifecycle ordering and final release.

## Assumptions

- The host process and operating system are not fully compromised.
- Trusted host code constructs Krosna, Zaslon, Ruslo, release destinations,
  authenticators, and effect executors; model/provider data cannot replace
  them.
- Adapters preserve bounds, typed metadata, lineage, and final egress checks.
- Protected executors require Propusk and no application code exposes a direct
  privileged bypass.
- Raw credentials are not independently copied into model-visible context.
- The built-in RealEffectExecutor is a narrow reference boundary for exact
  sandbox files and configured loopback HTTP, not a generic OS/network API.
- Runtime authentication is trusted deployment input. TLS/IPC, process and OS
  isolation, durable replay, cluster coordination, and core-dump policy are
  deployment responsibilities.

## Non-guarantees

Tkach does not solve prompt injection, semantic intent detection, hallucination,
perfect taint analysis, or every data leak. It does not protect a deliberately
bypassed Gateway, a fully compromised host/OS, or same-privilege out-of-band
effects. It does not provide durable distributed exactly-once effects,
forceful interruption of blocking synchronous calls, universal concurrent
filesystem race prevention, TLS/process isolation, or host-memory zeroization.
The current source has no SDK, MCP, streaming release, UI, cloud control
plane, or public internet gateway.

## Evidence boundary

The executable proof uses deterministic hostile providers, bounded fake
effects, real fixed local effects, and offline OpenAI fixtures. It demonstrates
the typed boundaries and declared workloads, not semantic model safety or
production deployment availability. The consolidated commands, counts,
mutation results, residuals, and scan limitation are in `EVIDENCE.md`.
