# Tkach Security Product Contract

Tkach Security is a deterministic security boundary around systems that use
probabilistic or compromised models.

> Assume the model is compromised. Tkach limits what the compromised model can
> actually do.

This contract describes guarantees only when the deployment conditions below
hold. It is intentionally shorter than the implementation and threat-model
documents.

## Guarantees

With a correctly integrated Gateway and protected executor:

1. Model-generated text and tool proposals cannot mint execution authority.
2. Protected execution requires a Tkach-issued, exact-scope `Propusk`.
3. A READ permission does not imply EXPORT permission.
4. Protected-derived data cannot be released to a protected public destination
   through the final `Diode`/`Zaslon` gates.
5. Untrusted DATA does not automatically become trusted CONTROL.
6. Broker-held secrets can be used through `Pechat` without entering ordinary
   model-visible context; raw reveal is denied.
7. Malformed, unknown, replayed, over-limit, failed, cancelled, or terminal
   privileged states fail closed.
8. `Krosna` decisions are deterministic and hard-deny rules cannot be
   negotiated by model output.
9. `Niti` lineage and `Metka` classification survive supported derivations and
   tool-result handoffs.
10. `Sled` evidence is structured and payload-free; it is not an authority
    input.

The OpenAI adapter adds a bounded, non-streaming Responses API boundary. It
does not change these guarantees or create a second policy engine.

## Required deployment conditions

The integrator must ensure that:

- every protected effect passes through the Tkach Gateway and the typed
  `ProtectedExecutor` boundary;
- the application provides no out-of-band executor, broker, release, or raw
  credential path to the model or adapter;
- broker-held secrets are not independently copied into model-visible input;
- adapters preserve required bounds, typed metadata, lineage, and final
  egress checks;
- trusted construction of Krosna, Zaslon, Diode, release destination, and
  executor is performed by trusted host code;
- policy labels and deployment configuration are treated as trusted inputs,
  not as model-controlled data;
- external tool results are returned through the Gateway rather than appended
  by an untrusted caller after authorization;
- the host process, operating system, runtime, and dependency supply chain are
  maintained within the deployment's security requirements.

## Non-guarantees

Tkach Security does not:

- detect every prompt injection, semantic paraphrase, hallucination, or bad
  model intention;
- make an LLM truthful, aligned, or non-hostile;
- prevent an integrator from deliberately routing around Tkach;
- protect a fully compromised host process, operating system, runtime, or
  deployment administrator;
- guarantee security for raw credentials deliberately inserted into model
  context outside Pechat;
- infer whether an allowed action is business-wise desirable;
- provide durable distributed replay protection or transaction semantics;
- make the current OpenAI adapter a production gateway;
- implement streaming, MCP, Anthropic, SDK, UI, cloud, or real executor
  orchestration.

## Integrator mental model

The model may suggest DATA and typed action proposals. Tkach decides whether a
proposal is authorized, whether information may cross a directional flow, and
whether a result may leave the final egress boundary. A successful model call
is never itself evidence of authorization.

## Contract failure

An integration that bypasses the Gateway, substitutes raw requests for
`Propusk`, strips `Niti`/`Metka`, exposes broker values, or releases output
without final `Diode`/`Zaslon` checks is outside this contract, even if the
underlying crates are used.
