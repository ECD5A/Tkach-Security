# Tkach Security Runtime Isolation Model

Status: R1 ownership contract implemented and locally verified for Production Runtime Hardening v0.1.

This document names ownership that can be implemented and audited. A box in a
diagram is not a process boundary by itself. BASIC, CONTROLLED, and SEALED are
deployment profiles with different assumptions, not claims that this crate can
magically protect a compromised host process.

## Ownership invariant

Only the Tkach security runtime may turn an authenticated request and a
provider proposal into a `Propusk`-mediated effect. The model/provider side is
never an owner of protected resources or authority.

## Four runtime zones

| Zone | Owns | May receive | Must not receive |
| --- | --- | --- | --- |
| MODEL SIDE | Untrusted client/model text, bounded provider requests, proposal data | Bounded DATA, fixed tool vocabulary, payload-free result categories | `Propusk`, `Decision` constructors, policy, executor, raw socket/file handle, raw credential, Klyuchnik broker |
| SECURITY RUNTIME | Authentication, request identity, lifecycle, budgets, Gateway, Krosna, Ruslo, Zaslon, Sled, cancellation and shutdown state | Authenticated principal, validated request, provider proposals | Raw client authority claims, provider authority claims, arbitrary endpoint/path/payload, raw secret |
| EFFECT SIDE | Tkach-owned executor, OS handles, fixed file/network binding, Klyuchnik broker and secret store | Fresh exact `Propusk`, trusted fixed configuration | Raw provider/client request, model callback, serialized permit, unrestricted path/endpoint, release authority |
| DEPLOYMENT CONTROL | Process users, ACLs, sandbox/job/container, TLS termination, core-dump and secret policy | Explicit configuration and operational events | Model-controlled configuration or secrets in logs/requests |

## Authority ownership

The following ownership is normative:

- The model/provider must not own `ProtectedExecutor`, raw filesystem handles,
  raw sockets, Klyuchnik's secret store, raw credentials, trusted policy
  constructors, Propusk minting, release authority, or shutdown authority.
- The client may authenticate, submit bounded DATA, and observe safe results;
  authentication is not Krosna authorization.
- The Gateway owns lifecycle order and staging, but Krosna remains the only
  authority issuer and Ruslo/Zaslon retain their independent decisions.
- The executor owns effect-specific OS operations and returns only bounded
  data or payload-free receipts. It does not accept a raw `ActionRequest`.
- Klyuchnik owns raw secret bytes. A secret-use result is a broker receipt or
  other explicitly typed bounded result; a raw secret is never a model value.

## Process-isolation profiles

### BASIC — one process, no protected effects

The Gateway, provider adapter, and rejecting/non-effect executor may share a
process. This profile is suitable for input containment and final egress
checks. It does not offer raw-secret isolation or protection from an
out-of-band application effect. The API still exposes only proposal and
`Propusk` boundaries so code can migrate to a stronger profile.

### CONTROLLED — one Tkach-owned effect path

The provider/model code remains untrusted and receives only bounded DATA. The
Gateway owns the executor reference and invokes it only after Krosna/Ruslo/
Zaslon gates. The application must not retain an alternate executor, raw
credential, raw path, or raw socket path. This is an API/deployment discipline
within one process; a same-process compromise remains outside the guarantee.

### SEALED — separate effect authority and secret custody

The security runtime and effect side are separate operational owners, ideally
separate processes with distinct OS identities, filesystem ACLs, job/container
boundaries, and explicit authenticated IPC. The effect side accepts a narrow
validated request or one-time capability reference and returns bounded
payload-free results. TLS/IPC framing, OS hardening, crash-dump policy, and
secret injection are deployment responsibilities. This repository proves the
contract and local reference path, not a universal process supervisor.

## API shape required for future process splitting

The current in-process `Gateway` remains the only composition entry point. To
keep a future SEALED split possible:

1. transport messages are bounded data with explicit request and lifecycle IDs;
2. authentication proof is separate from model input and never maps directly
   to an action capability;
3. `Propusk`, `Decision`, executor references, and broker values are not wire
   types;
4. effect requests are reconstructed from trusted fixed bindings and fresh
   authorization, rather than accepting a caller-supplied path/endpoint/
   payload;
5. results and receipts are bounded, payload-free where required, and carry
   explicit uncertainty;
6. shutdown, cancellation, replay, and concurrency state are owned by the
   security runtime, not the provider.

## Bypass and residual trust

No Rust API can stop an integrator from opening a file or socket directly if
that integrator has the same host privileges. Therefore the production claim
requires all protected effects to be routed through the Tkach-owned executor
and, for SEALED, separate OS enforcement. A direct application path is an
out-of-band bypass and invalidates the claim for that effect; it is not hidden
by the diagram or counted as a Tkach denial.

Host compromise, kernel compromise, malicious deployment configuration, and
the inability of portable Rust to provide universal no-follow filesystem
transactions remain explicit limitations. The strongest deployable profile
is the narrowest fixed effect catalog plus a separately reviewed OS adapter,
not a general shell or filesystem API.

## Acceptance evidence

R1 passes only when source review and tests show that public provider/client
APIs cannot obtain a `Propusk`, executor/broker reference, raw secret, trusted
policy constructor, arbitrary endpoint/path/payload, or release authority; and
when the transport/runtime interfaces can be represented as bounded data for a
future process boundary. This document is not itself proof of those tests.
