# OpenAI Provider Boundary Threat Model

Status: P0 design baseline for the Real Provider Phase v0.1. This document
describes the boundary before the provider-specific implementation is added.
It does not grant OpenAI, a model, or an adapter any Tkach authority.

## Security invariant

> OPENAI OUTPUT IS MODEL DATA, NEVER TKACH AUTHORITY.

The OpenAI API is an untrusted remote model boundary. A model response may be
fully attacker-controlled, whether the cause is direct prompt injection,
indirect prompt injection, poisoned retrieved content, malicious tool output,
provider compromise, or model error. Tkach security must remain correct when
the model intentionally returns the most dangerous valid-looking response.

## Intended flow and trust zones

```text
Client / untrusted request
        |
        v
Gateway ingress Zaslon + Gnezdo DATA containment
        |
        v
bounded ProviderRequest
        |
        v
OpenAI adapter -- HTTPS + infrastructure credential --> OpenAI Responses API
        ^                                                |
        |                                                v
        +-- bounded strict parser <-- opaque untrusted response
        |
        v
Gateway staging: text DATA + ActionRequest proposals
        |
        +--> Krosna / Diode / Zaslon --> release or deny
        |
        +--> kernel-issued Propusk --> protected executor / Pechat
```

The provider-independent contract is source-backed by:

| Boundary | Evidence and invariant |
| --- | --- |
| Gateway to provider | `crates/tkach-gateway/src/provider.rs:105-263`: the provider sees bounded inputs, metadata, a fixed tool vocabulary, and a sink that only stages text or raw `ActionRequest` proposals. |
| Provider staging | `crates/tkach-gateway/src/provider.rs:265-329`: chunks/actions are bounded and retained until the Gateway completes its checks. |
| Final output gate | `crates/tkach-gateway/src/gateway.rs:267-344,462-501`: complete output is size-, Diode-, and egress-Zaslon-checked before release. |
| Action boundary | `crates/tkach-gateway/src/gateway.rs:379-461`: all proposals are preflighted by Krosna and only the resulting Propusk reaches the executor. |
| Core authority | `crates/tkach-core/src/domain.rs:729-779` and the Propusk boundary: an ActionRequest is a request, not execution authority. |
| Secret boundary | `crates/tkach-core/src/pechat.rs` and the Gateway tool boundary: provider-visible handles/results do not expose broker-held raw secrets. |

The line references identify the baseline inspected for this P0 document;
future edits must keep the claims and controls synchronized with code.

## Assets and invariants

- Krosna policy, Zaslon hard-deny rules, Diode flow rules, and the fixed tool
  catalog must not be changed by provider data.
- A raw provider response must never become a Decision, Propusk,
  DeclassificationPermit, ProtectedExecutor, Pechat broker, or trusted
  provenance/classification value.
- Model text is data. It is released only after Gateway-owned final flow and
  content gates pass.
- A function call is only an ActionRequest proposal. The function name,
  arguments, call ID, and response ID are untrusted identifiers/data.
- Protected tool results may be sent back to the model only through the
  existing bounded context path. Their Niti/Metka remain Gateway-owned and
  must be included in later conservative output derivation.
- No failed, timed-out, cancelled, partial, replayed, or malformed provider
  turn may execute a pending irreversible action.
- Infrastructure credentials remain outside model-visible input, output,
  Sled, errors, Debug, fixtures, and repository history.

## Threat scenarios

The scenarios below are hypotheses to drive implementation and tests, not
claims that a vulnerability already exists.

| Priority | Attacker story and capability gain | Expected control and test |
| --- | --- | --- |
| Critical | A model returns a forged `Decision`, `Propusk`, Sled record, trusted metadata, or authority statement. | The adapter has no authority-bearing constructors or Gateway callbacks; only typed ActionRequest proposals are emitted. Unknown fields and response types fail closed. |
| Critical | A function call names an unknown tool, a built-in tool, MCP, web search, file search, computer action, or a provider-side effect. | The request advertises only the fixed Tkach-controlled custom functions; the parser allowlist rejects every other output item and no provider tool is enabled. |
| Critical | Malicious arguments widen a scope, select a secret, change a destination, or smuggle a second operation. | Function schemas and the adapter parser accept only the minimal known argument shape; all resulting ActionRequests are reconstructed from trusted tool mapping and still require Krosna authorization. |
| Critical | The adapter returns a raw secret, API key, or provider error body to the model/client/log. | API keys are opaque infrastructure configuration; response/error bodies are bounded and payload-free at the public error boundary; secret-backed tool results are receipts or protected data governed by Gateway. |
| High | A response contains a protected tool result request followed by public-looking text, or provider metadata claims the result is public/declassified. | Provider metadata is ignored as authority. Gateway derives output from all model inputs and applies Niti/Metka, Diode, and egress Zaslon before release. |
| High | A partial stream, chunk seam, duplicate event, missing terminal event, or malformed SSE event is released or executes an action. | Streaming is a separate buffered mode with event/byte/time limits, a required terminal event, duplicate/sequence checks, and no fragment release before final Gateway gates. |
| High | A timeout/cancellation after an action proposal leaves an irreversible effect or stale Propusk. | Adapter performs no automatic retry; provider failure is returned before Gateway authorization/execution, and Gateway owns per-lifecycle staging and effect ordering. |
| High | A retry or replay of a response ID or function call ID repeats a protected effect. | IDs are opaque replay markers only. The adapter tracks bounded seen IDs, rejects duplicates, and never uses IDs as authority or as an executor key. |
| High | The provider follows a prompt injection embedded in a client message, tool result, or model-generated text. | Detection is not a security proof. Gnezdo, Krosna, Propusk, Niti/Metka, Diode, Pechat, and Zaslon remain deterministic boundaries. |
| Medium | Oversized output, item count, arguments, headers, or error body causes uncontrolled allocation or CPU work. | Raw response length, streaming reads, item counts, text, arguments, request serialization, and HTTP error bodies have explicit bounded limits. |
| Medium | Redirects, proxy behavior, or a model-controlled endpoint sends the credential elsewhere. | Base URL is trusted configuration, HTTPS-only, no credentials/query/fragment, redirects are disabled, and no provider/model field controls the destination. |
| Medium | OpenAI persistence or remote conversation state becomes hidden Tkach security state. | Non-streaming requests set `store:false`, do not use background mode, conversations, or `previous_response_id`; Tkach/Gateway owns lifecycle state. |
| Medium | Provider output item order, role, annotation, response status, or error shape is confused with an assistant message. | Strict allowlisted parsing accepts only completed assistant text and Tkach custom function calls. Unknown/malformed structures deny. |
| Low | Opaque response/call IDs or configured model labels appear in diagnostics. | IDs are bounded and payload-free diagnostics are preferred; no credential or protected payload is logged. These labels never affect policy. |

## Boundary-specific controls

### Client and Gateway ingress

The adapter receives only the Gateway's bounded `ProviderRequest`. Client
roles, metadata, and declared tool labels are data and cannot extend the
trusted function catalog. The adapter must not deserialize provider wire
structures into core security types.

### OpenAI request

The request builder uses only trusted adapter configuration for the model,
base URL, timeout, and credential. It sends `store: false`, disables
background/conversation state, disables provider built-ins and MCP, and sets
the exact custom function definitions. Client/model text cannot modify these
fields. Arbitrary metadata is not forwarded as OpenAI authority or persistence
state.

### OpenAI response

The response body is bounded before parsing. The parser accepts only:

1. completed assistant text items; and
2. completed `function_call` items whose names belong to the fixed Tkach
   custom-function catalog.

Arguments are strings containing bounded strict JSON. The adapter validates the
known shape and reconstructs an ActionRequest using fixed operation,
capability, resource, and destination semantics. It never trusts a model
argument as a capability grant or as a security label.

### Tool result return

When Gateway supplies a read-only tool result for a later provider turn, the
adapter maps it to an OpenAI `function_call_output` DATA item paired with the
opaque provider call ID. The result is not a control message, and the adapter
does not send Niti/Metka as provider authority metadata. Gateway retains the
actual lineage/classification and derives subsequent output conservatively.

### HTTP/TLS

Use a mature HTTP client and TLS implementation. The adapter must bound
success and error bodies, set a finite timeout, reject redirects, construct
the endpoint from trusted configuration, and expose only static payload-free
transport errors. It must not log request headers or credential-bearing URLs.

## Assumptions and non-guarantees

- The host process, operating system, TLS implementation, and trusted adapter
  configuration are not fully compromised.
- OpenAI can observe and process data deliberately sent to it; `store:false`
  is a request-level application-state control, not a claim that no service
  telemetry or network intermediary can ever observe content.
- The deployment permits the specific protected reads that it intentionally
  sends to the provider. Diode still governs whether a result can leave the
  model boundary.
- This phase does not solve semantic prompt injection, model compromise,
  perfect taint analysis, or all possible data leakage.
- This phase does not implement provider-side tools, remote MCP, conversations,
  background mode, automatic retry, or irreversible provider effects.
- Streaming must remain buffered and fail closed; token-by-token public release
  is not a goal of this phase.
- Live OpenAI tests, if enabled, prove protocol correctness only. Synthetic
  hostile providers remain the security oracle.

## Review record

This model was produced from a sequential source review because delegated
architecture workers were unavailable in the current environment. It must be
reconciled with the adapter implementation and its adversarial tests before
the provider checkpoint.

Repository: Tkach-Security
Version: 7c80701243cadfdbb7f37d15830cb46021b993d0
