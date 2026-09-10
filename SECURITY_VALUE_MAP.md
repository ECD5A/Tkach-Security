# Security Value Map

This is the canonical value map for the nine Tkach security primitives. Each
row names the threat, the invariant that must hold, a realistic workload that
exercises it, and the concrete security consequence of removing it. Gateway
and provider adapters are integration boundaries, not substitute primitives.

| Primitive | Threat | Invariant | Realistic workload | What breaks if removed | Classification |
| --- | --- | --- | --- | --- | --- |
| Krosna | A model proposal or caller requests an unauthorized effect | Only deterministic policy with fixed hard-deny precedence can authorize a typed action | Coding-agent read plus exact project write; hostile scope/public-write proposal | Unauthorized proposals can become authority or policy order can be bypassed | Required enforcement |
| Propusk | A raw request reaches an executor or widens its scope | Execution accepts only kernel-issued authority bound to principal, operation, capability, resource, and destination | Approved file write and Klyuchnik use reach a fake executor only as scoped tokens | An executor or adapter can invoke protected effects from an untrusted request | Required enforcement |
| Ruslo | Protected information is exported or direction is confused | READ, EXPORT, and TRANSFER are separate directed decisions carrying provenance and classification | Internal protected summary succeeds; public export is denied; explicit Public export is independently allowed | Read can imply export, reverse routes can be inferred, or protected data can cross egress | Required enforcement |
| Zaslon | Formal blocked content/action is smuggled through normalization or chunk seams | Canonical hard-deny rules and terminal stream decisions are deterministic | Cross-chunk egress block prevents a staged write/release | A formal deny pattern or action block can be bypassed at representation/lifecycle seams | Required enforcement |
| Gnezdo | Instructions or imported documents impersonate trusted control | Untrusted content remains bounded DATA with no public promotion path to authority | Hostile issue text is analyzed while authority-forgery/DATA-to-CONTROL text creates no effect | Prompt injection can change representation and enter a control path | Required security state |
| Niti | Derived output loses its source lineage | Supported derivations retain bounded parent provenance and unknown state is conservative | Protected read and follow-up tool result retain origin through model/provider turns | Ruslo, Metka, and evidence can no longer distinguish protected origin | Supporting security state |
| Metka | A model or transformation relabels protected data as public | Classification joins monotonically; lowering needs a trusted opaque permit | Protected summary remains protected at the public-release gate | Protected data can be relabeled and exported by a model claim | Supporting security state |
| Klyuchnik | A model sees or reveals raw credential material | Secrets stay broker-side; exact `secret.use` is the only usable route and reveal is denied | Sealed agent uses an opaque handle, receives a receipt, and cannot reveal/export raw bytes | Credentials can enter model context, diagnostics, or an uncontrolled executor | Required enforcement |
| Sled | Denials/effects are unauditable or diagnostics leak payloads | Evidence is bounded, typed, payload-free, and never an authority input | Attack matrix reports denial reason/effect counts without fake secret or hostile payload | Operators lose safe diagnosis or add unsafe logging that becomes an exfiltration path | Diagnostic security state |

## Composition conclusion

The minimum physical enforcement core is Krosna + Propusk + Ruslo + Zaslon +
Klyuchnik's broker boundary. Gnezdo, Niti, and Metka are not redundant labels:
they carry different data/control, lineage, and sensitivity state consumed by
those gates. Sled is not an authorization primitive, but removing it weakens
safe integration and deny diagnosis. Gateway owns lifecycle ordering and final
release; it does not replace any primitive or create a second policy engine.

The workload column is evidence from the offline Product Proof harness, not a
claim that a fake executor models production transactions or a live provider.

## Runtime composition value

The runtime service is deliberately not a tenth branded primitive. It composes
the nine primitives and owns a different concern: bounded authenticated
admission, lifecycle identity, cancellation, shutdown, and safe receipts. If
the runtime layer is bypassed, authentication/replay/resource guarantees are
lost even though Krosna and Propusk may still protect an effect reached through
the typed path. If Krosna/Propusk/Ruslo/Zaslon/Klyuchnik are bypassed, runtime
authentication alone must not authorize the effect. This separation is tested
as authentication-pass/authorization-deny and invalid-auth/zero-effect cases.
