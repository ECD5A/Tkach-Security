# Architecture

## Implemented baseline

The repository currently contains one provider-independent Rust workspace
member, `tkach-core`. The crate has an explicit domain module with validated
security types and a synchronous Krosna evaluator. It has no provider,
network, database, runtime, or external execution dependency.

Krosna applies these gates in a fixed order: invalid principal/context,
unknown operation or destination, trusted-control requirements, protected
public-export denial, then policy rules ordered by `HardDeny`, `Deny`,
`RequireApproval`, `Allow`; an unmatched request denies. Within one effect
class, the lexicographically smallest rule ID supplies stable evidence. Policy
rule order therefore does not alter authorization.

## Target Strong Core shape

```text
validated SecurityEnvelope
          |
          v
        Krosna
   /      |       \
Zaslon  Propusk  Diode
   \      |       /
      decision + Sled
          |
     Pechat boundary
```

Gnezdo contains untrusted content in a data lane. Niti and Metka preserve
provenance and conservative classification. No model output is trusted as
policy or authority. The protected executor boundary accepts only kernel-issued
authorization once that mandate is implemented.

## Trusted Computing Base

At the checkpoint, the TCB is intended to be the typed domain and synchronous
policy kernel in `tkach-core`, plus Rust's type/visibility rules. Policy and
provenance deserialization re-run validation before entering the domain.
Adapters, logging, serialization boundaries, and provider integrations must not
define security semantics.

## Future, not implemented

OpenAI, Anthropic, MCP, HTTP gateways, cloud services, SDKs, dashboards, and
human approval services are explicitly deferred until after owner review of the
Strong Core checkpoint.
