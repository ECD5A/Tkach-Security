# Simplification Red-Team Results

This is the A17 adversarial review of the pruning changes after implementation.

| Attack hypothesis | Probe | Result |
| --- | --- | --- |
| Removing `DataLane` loses DATA containment | Construct content through `Gnezdo`, inspect context, attempt promotion | Rejected: context remains Model/None/Untrusted/Data/Unknown; promotion still fails |
| Removing `Pechat` facade removes secret isolation | Use exact secret route, alter one route dimension, request reveal | Rejected: `SecretBroker` accepts only matching Propusk; reveal always denies |
| Removing `ScriptedProvider` alias changes provider lifecycle | Run Gateway with `DeterministicProvider` and hostile/failure providers | Rejected: lifecycle, staging, replay, and final gates remain unchanged |
| Removing duplicate checks widens authority | Try raw action, wrong scope, unknown capability, secret destination, protected export | Rejected by Propusk, Krosna, Diode, Pechat, and executor boundaries |
| Simplified defaults become permissive | Submit unknown operation/destination/context or malformed provider state | Rejected: default-deny and parser/lifecycle fail-closed paths remain active |
| Fewer layers permit partial effects | Fail after staging, deny final output, or submit a mixed batch | Rejected: preflight and final egress occur before irreversible execution |
| Diagnostics become an authority input | Serialize/reuse Sled evidence or inspect public debug surfaces | Rejected: evidence is payload-free and not deserializable authority |

## Evidence

- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  passed after the pruning fix.
- Debug workspace matrix passed with 206 tests and zero failures.
- Targeted Gnezdo/Pechat mutation run passed with 46/55 mutants caught and no
  unexplained security-relevant survivor.
- `git diff --check` passed and no removed symbol remains in source callers.

No simplification defect was found that required revert or architecture
redesign.
