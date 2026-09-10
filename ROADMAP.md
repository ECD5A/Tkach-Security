# Roadmap

This file is the compact project map. It describes current repository state
and active planning; historical reports and `DEVELOPMENT.md` contain detailed
evidence, not instructions.

## CURRENT

Strong Release Candidate v0.1, entering boundary/product risk review after
authoritative documentation and state consolidation. The source baseline is
local tag `production-runtime-v0.1` at commit
`41e9ca0a374cfb95ac1a1ed3a5b22ce6445d9283`.

## DONE

- Strong Core typed domain and all canonical primitives:
  `Krosna`, `Propusk`, `Ruslo`, `Zaslon`, `Gnezdo`, `Niti`, `Metka`,
  `Klyuchnik`, and `Sled`.
- Provider-independent bounded Gateway with hostile-provider, composition,
  product-proof, and integration-proof evidence.
- Narrow non-streaming OpenAI Responses adapter over the existing authority
  boundary, with offline fixtures and opt-in live guard only.
- Narrow real filesystem/loopback effect boundary with explicit residuals.
- Bounded authenticated loopback runtime, lifecycle replay, cancellation,
  shutdown, safe receipts, and explicit uncertain-effect semantics.
- Full local production-runtime validation, documentation, checkpoint, and
  annotated tag `production-runtime-v0.1`.

## NEXT

1. review protected-effect and deployment residuals;
2. choose the next product boundary only from demonstrated risk and useful
   workload evidence;
3. run the engineering loop for each selected hardening phase;
4. create `strong-release-candidate-v0.1` only after its checkpoint is
   genuinely satisfied.

## NOT IMPLEMENTED AT THIS BASELINE

There is no MCP adapter, provider SDK, streaming release API, generic
executor, public internet gateway, UI, cloud control plane, TLS/process
supervisor integration, durable distributed replay, or universal
handle-relative filesystem transaction. These are current implementation
facts, not permanent constitutional prohibitions. Any future boundary must
first satisfy `RELEASE_CANDIDATE_PLAN.md` and preserve the existing authority
model.

## AUTHORITATIVE DOCUMENTS

- `CURRENT_BASELINE.md` — what exists now and what is proven;
- `RELEASE_CANDIDATE_PLAN.md` — active phase and release bar;
- `Tkach Security — MASTER_MANDATE.md` — permanent constitution;
- `PRODUCT_CONTRACT.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`, and threat
  models — current contracts and limitations;
- reports/checkpoints — historical evidence only.
