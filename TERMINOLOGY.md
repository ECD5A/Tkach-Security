# Tkach Security Terminology

Branded names describe conventional security roles; they are not a license to
infer behavior beyond the implementation and Product Contract.

| Tkach term | Conventional security term | Practical meaning |
| --- | --- | --- |
| Krosna | Deterministic authorization policy engine | Evaluates typed actions with default deny and hard-deny precedence |
| Propusk | Scoped execution capability | Kernel-issued authority accepted by protected executors |
| Ruslo | Directional information-flow control | Separates read, export, and transfer decisions |
| Zaslon | Formal content/action deny boundary | Canonical matching and bounded stream lifecycle |
| Gnezdo | DATA/CONTROL containment | Keeps untrusted content from becoming trusted control |
| Niti | Provenance lineage | Retains source history through derivation |
| Metka | Conservative sensitivity label | Carries monotonic classification into enforcement |
| Klyuchnik | Secret-use isolation / broker boundary | Keeps raw secrets broker-side and denies reveal |
| Sled | Structured security evidence | Bounded payload-free decision trace for diagnostics |

The model is not expected to construct or mutate these concepts. Trusted host
configuration and the Gateway compose them; provider output remains untrusted
DATA and typed proposals.
