# Primitive Necessity and Architecture Review

This review answers A2-A5 and A8-A11 against the frozen baseline. Branded
names remain part of the product vocabulary, but a name alone is not treated
as proof that a separate subsystem is required.

## Minimal enforcement decomposition

| Primitive | Conventional security role | Concrete runtime mechanism | Decision |
| --- | --- | --- | --- |
| Krosna | Deterministic authorization policy engine | Ordered rule evaluation, hard deny, exact authorization | **Required** |
| Propusk | Scoped execution capability | Private kernel-issued request/grant token accepted by `ProtectedExecutor` | **Required** |
| Ruslo | Directional information-flow control | Source/destination/operation/provenance/classification evaluation | **Required** |
| Klyuchnik | Secret-use isolation | Opaque `SecretHandle`, `SecretBroker`, exact secret-use token, reveal denial | **Required**; remove only the empty facade |
| Zaslon | Formal content/action boundary | Canonical matcher, hard deny, bounded stream lifecycle | **Required** |
| Gnezdo | DATA/CONTROL containment | Validated untrusted context and no public promotion path | **Required security state** |
| Niti | Provenance lineage | Bounded provenance roots and derivation lineage | **Required supporting state** |
| Metka | Conservative sensitivity classification | Monotonic classification join and declassification permit boundary | **Required supporting state** |
| Sled | Structured decision evidence | Bounded payload-free trace of kernel decisions | **Required diagnostic output** |

## Primitive-by-primitive answers

### Krosna

Krosna blocks unauthorized protected effects, preserves deterministic deny
precedence, and is the only production authority issuer. Ruslo and Zaslon
consume related inputs but do not authorize execution, so merging them would
create an ambiguous policy engine. Keep as a distinct runtime mechanism.

### Zaslon

Zaslon blocks configured formal content and action representations, including
chunk-boundary bypasses and premature stream release. Krosna's policy decision
and Ruslo's flow decision do not inspect the same grammar or lifecycle. Keep.

### Gnezdo

Gnezdo prevents attacker-controlled content from carrying authority or being
promoted to control. Its `UntrustedContent` and `SecurityContext` are the
runtime mechanism. The removed `DataLane` marker only restated values already
stored in that context and had no independent enforcement.

### Propusk

Propusk blocks raw action requests from reaching protected execution and binds
the exact authorized scope. Its private construction and executor trait are a
real type-level boundary. Keep.

### Niti and Metka

Niti preserves where data came from; Metka preserves how sensitive it is.
Ruslo consumes both, but neither can replace the other: lineage and
classification are different security dimensions. Keep as one supporting
module with two explicit concepts, not merge their semantics.

### Ruslo

Ruslo blocks protected information export and direction confusion. Krosna's
action authorization is not an information-flow decision. The repeated
`PublicExternal` checks are defense-in-depth at different boundaries, not
duplicate policy engines: Ruslo is the authoritative flow decision, Krosna
and Gateway reject incompatible action routes before execution or release.
Keep.

### Klyuchnik

Klyuchnik blocks raw secret disclosure and isolates broker use behind an exact
Propusk. `SecretBroker`, `SecretHandle`, `FakeBroker`, and the exact route are
real mechanisms. The empty `Klyuchnik::new()` facade has no state, enforcement,
or integration consumer; remove only that facade while retaining the branded
term in documentation and module vocabulary.

### Sled

Sled provides bounded, payload-free evidence needed to explain decisions and
debug safe integration. It is not an authority source. The trace is a real
diagnostic runtime mechanism used by Gateway; the hostile model and fake
executor are executable security-test infrastructure and remain until an
equally strong test-only packaging is available.

## Duplication review

- Krosna, Ruslo, and Gateway each validate their own boundary. Their checks
  have different inputs and failure consequences; merging them would blur the
  authority/flow/egress trust boundaries.
- The OpenAI adapter validates provider wire representation and maps only to
  raw proposals. It does not repeat Krosna or Ruslo policy.
- Fake executors and brokers intentionally repeat exact-route checks as
  defense-in-depth at the final effect boundary. Removing those checks would
  make test evidence weaker.
- Parser, collection, replay, and transport limits belong to their respective
  protocol boundaries; centralizing them across crates would either widen a
  trust boundary or hide a required limit.

## Public API classification

### User/integrator API

Validated domain values, `Policy`/`Krosna`, `Zaslon`, `Ruslo`, `TaggedData`,
`SecretHandle`/`SecretBroker`, `Propusk`/`ProtectedExecutor`, and Gateway
request/result/provider traits.

### Provider-adapter API

`OpenAiConfig`, `OpenAiProvider`, and payload-free `ConfigError`. Wire,
transport, parser, response IDs, and replay state remain private.

### Internal security API

Private constructors, `CapabilityGrant::issue`, `AuthorizedAction::issue`,
context/flow mappers, decision construction, staging, and lifecycle
transitions. These remain private or crate-private.

### Testing/integration infrastructure

`FakeBroker`, fake Gateway tools, scripted/hostile providers, and the Sled
testbed are public because current cross-crate integration tests exercise
actual typed boundaries. They carry no authority constructors and are marked
as fakes in their API documentation. A future test-only packaging change is a
separate migration, not a reason to weaken this phase's regression coverage.

## Deliberate pruning decisions

| Candidate | Action | Security property preserved |
| --- | --- | --- |
| `DataLane` zero-sized marker | Remove | `Gnezdo::contain` still produces an immutable DATA/None/Untrusted context |
| `Klyuchnik` zero-sized facade | Remove | `SecretBroker` exact-token use and reveal denial remain unchanged |
| `ScriptedProvider` type alias | Remove | `DeterministicProvider` and all provider lifecycle tests remain unchanged |
| Krosna/Ruslo/Gateway boundary checks | Keep | Independent authorization, flow, and final-egress gates remain distinct |
| Sled fake/testbed code | Keep | Executable hostile-model and protected-effect evidence remains available |

No security-critical runtime logic is merged or deleted in this review. The
three removals are API/code pruning only and must be followed by the complete
baseline test matrix and a simplification red-team pass.

## Simplification red-team checkpoint

The first pruning cycle was challenged after implementation:

- repository search confirmed no production or test caller still depends on
  the removed `DataLane`, `Klyuchnik::new()`, or `ScriptedProvider` symbols;
- Gnezdo context tests still prove DATA/None/Untrusted/Unknown state and denied
  promotion;
- Klyuchnik tests still prove exact-token secret use, reveal denial, and bounded
  broker memory;
- Gateway/Core tests still prove Propusk-only execution, protected export
  denial, lifecycle ordering, and no partial effect after failure;
- targeted mutation testing of the retained Gnezdo/Klyuchnik paths tested 55
  mutants: 46 caught and 9 unviable, with no unexplained security survivor;
- the post-pruning workspace baseline is 206 passing tests: two removed tests
  covered only the deleted marker/facade APIs, while all security scenarios
  remain covered.

The reduction therefore removed vocabulary-only API surface without removing
an enforcement point or making a safe default permissive.
