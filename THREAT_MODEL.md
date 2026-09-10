# Threat Model

The Strong Core assumes the model can be fully attacker-controlled. It protects
the deterministic authority boundary, not the model's reasoning process.

| Attack | Asset | Trust boundary | Expected behavior | Failure mode to test |
|---|---|---|---|---|
| Direct/indirect prompt injection | Policy and capabilities | Gnezdo data/control lanes | Content remains data; no authority transition | Natural language creates privilege |
| Malicious web/RAG/document/email/tool/MCP data | Authority | Untrusted ingress to domain | Provenance and lane remain untrusted | Authority laundering |
| Compromised model/agent | Protected actions/data | Action request to Krosna | Request alone is not Propusk | Raw request executes |
| Capability escalation/scope widening | Resources | Propusk scope check | Deny outside exact scope | Parent/child confusion |
| Exfiltration | Protected data | Diode/Zaslon egress | Directional flow denied | Read implies export |
| Provenance/Metka stripping | Lineage/classification | Transformations | Conservative state retained | Originless or public output |
| Secret-handle disclosure | Broker secret | Pechat | Handle is opaque; raw secret stays broker-side | Debug/error/evidence leak |
| Malformed/ambiguous input | Policy state | Boundary validation | Reject or deny | Fail-open parse/evaluation |
| Unicode/chunk/encoding bypass | Formal Zaslon rules | Canonicalization/matcher | Equivalent forms behave consistently | Representation bypass |
| Policy conflict/evaluation failure | Authorization | Krosna | Deterministic deny/restricted result | Failure becomes allow |
| Logging leakage | Secret material | Sled/logging | Identifiers only | Payload in evidence |
| Principal/provenance spoofing | Authority and flow decisions | Public context/wire boundary | Untrusted identity is model/data only; trusted provenance is not forgeable | Metadata changes policy or Diode route |
| Originless derivation laundering | Classification and export controls | Gnezdo/Niti/Metka transforms | Unknown parent state remains Unknown | Empty parents become Public |

The table is a living summary; each completed mandate adds executable coverage
and records discovered weaknesses in `DEVELOPMENT.md`. Red-team coverage also
asserts that diagnostic formatting does not echo untrusted or broker-held
payloads and that streaming normalization cannot be bypassed at chunk seams.

The enforcement testbed exercises this table without a real model, network, or
provider: hostile typed proposals are evaluated by Krosna, every decision is
recorded in bounded Sled evidence, and only a kernel-issued `Propusk` can reach
the fake executor. Secret-destination proposals require an explicit Pechat
broker; an absent broker does not fall back to executor execution.
