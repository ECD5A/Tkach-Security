# Threat Model

The Strong Core assumes the model can be fully attacker-controlled. It protects
the deterministic authority boundary, not the model's reasoning process.

The first real-provider boundary preserves that assumption across the remote
OpenAI hop. The adapter treats the API and returned model data as hostile,
keeps the API credential outside model data and diagnostics, and maps only
fixed known function names to raw proposals. Provider IDs, metadata, status,
tool arguments, and model claims are never security authority; Gateway-owned
Krosna/Propusk, Niti/Metka, Ruslo, Zaslon, and Klyuchnik remain the enforcement
planes.

The production runtime extends the same invariant across a local caller:
authentication proves a caller may enter the bounded Gateway lifecycle, but
does not authorize an effect. The runtime ledger owns request/lifecycle
identity, shutdown, cancellation, and per-instance replay state; Krosna still
owns authorization and only Propusk reaches the effect side. The local carrier
is loopback-only and length-prefixed, with deployment TLS/process isolation and
durable replay explicitly outside the crate.

| Attack | Asset | Trust boundary | Expected behavior | Failure mode to test |
|---|---|---|---|---|
| Direct/indirect prompt injection | Policy and capabilities | Gnezdo data/control lanes | Content remains data; no authority transition | Natural language creates privilege |
| Malicious web/RAG/document/email/tool/MCP data | Authority | Untrusted ingress to domain | Provenance and lane remain untrusted | Authority laundering |
| Compromised model/agent | Protected actions/data | Action request to Krosna | Request alone is not Propusk | Raw request executes |
| Model-controlled write/execute effect | Internal and protected destinations | Action-to-Ruslo source mapping | Non-read effects are model-originated | Model-to-Internal deny bypassed by resource-source confusion |
| Capability escalation/scope widening | Resources | Propusk scope check | Deny outside exact scope | Parent/child confusion |
| Exfiltration | Protected data | Ruslo/Zaslon egress | Directional flow denied | Read implies export |
| Provenance/Metka stripping | Lineage/classification | Transformations | Conservative state retained | Originless or public output |
| Secret-handle disclosure | Broker secret | Klyuchnik | Handle is opaque; raw secret stays broker-side | Debug/error/evidence leak |
| Malformed/ambiguous input | Policy state | Boundary validation | Reject or deny | Fail-open parse/evaluation |
| Unicode/chunk/encoding bypass | Formal Zaslon rules | Canonicalization/matcher | Equivalent forms behave consistently | Representation bypass |
| Intermediate stream release | Egress content | Zaslon stream lifecycle | `NeedMoreData` is not releasable; only explicit finish can clear | Partial scan treated as allow |
| Post-finish stream extension | Finalized content decision | Zaslon stream lifecycle | Finished streams reject later input | Content appended after `Clear` |
| Policy conflict/evaluation failure | Authorization | Krosna | Deterministic deny/restricted result | Failure becomes allow |
| Logging leakage | Secret material | Sled/logging | Payload-free categories plus trusted policy labels | Request payload in evidence |
| Principal/provenance spoofing | Authority and flow decisions | Public context/wire boundary | Untrusted identity is model/data only; trusted provenance is not forgeable | Metadata changes policy or Ruslo route |
| Originless derivation laundering | Classification and export controls | Gnezdo/Niti/Metka transforms | Unknown parent state remains Unknown | Empty parents become Public |
| Secret-destination executor bypass | Broker-held secret | Propusk/ProtectedExecutor/Klyuchnik | Any direct SecretBroker execution is rejected | Non-secret action reaches broker destination |
| Resource exhaustion | Core availability and bounded state | Wire and collection boundaries | Oversized rules, aggregate patterns, lineage, content, model input, trace, and broker state reject | Allocation or matching work grows without bound |

Additional runtime rows are:

| Attack | Asset | Trust boundary | Expected behavior | Failure mode to test |
|---|---|---|---|---|
| Unauthenticated/replayed runtime request | Gateway/effect admission | Runtime frame and identity ledger | Authentication precedes Gateway; request/lifecycle IDs are one-instance terminal markers | Caller enters provider/effect or repeats an uncertain lifecycle |
| Transport peer stalls or sends oversized frame | Runtime availability | Loopback framed listener | Read/write timeouts, four-byte length bound, no compression, one connection at a time | Unbounded body allocation, queue, or worker growth |
| Shutdown/cancellation race | Effect ordering and outcome truth | Runtime/Gateway lifecycle | Stop admission, check cancellation before effects, preserve unknown outcome | Effect runs after barrier or unknown is retried |

The table is a living summary; each security-sensitive change adds executable
coverage and records relevant public contract or changelog updates. Red-team coverage also
asserts that diagnostic formatting does not echo untrusted or broker-held
payloads and that streaming normalization cannot be bypassed at chunk seams or
released before finalization. Public metadata constructors are also exercised
to ensure a caller cannot relabel model data as trusted or protected source
material. Request-controlled Sled fields are category-projected; trusted policy
rule labels remain separately identified for explainability. Klyuchnik handle
existence remains an authorized-operation metadata distinction, not a secret
value channel.

The enforcement testbed exercises this table without a real model, network, or
provider: hostile typed proposals are evaluated by Krosna, every decision is
recorded in bounded Sled evidence, and only a kernel-issued `Propusk` can reach
the fake executor. Secret-destination proposals require an explicit Klyuchnik
broker; an absent broker does not fall back to executor execution.

## Product Proof adversarial evidence

The B0-B22 offline harness turns this threat table into paired deterministic
workloads. It covers prompt injection, authority forgery, DATA-to-CONTROL
attempts, scope escalation, protected export, secret reveal, replay, malformed
provider output, timeout/failure/cancellation, and premature release. The
oracle counts typed effects, reads, external sends, decisions, provider turns,
and secret-surface occurrences; it does not trust provider text. The checked-in proof suite
reports zero defined false allows and no raw fake secret in result,
error, trace, or broker-debug surfaces. This is bounded evidence for the
offline fake environment, not a claim that semantic model compromise or a
host-level bypass is solved.
