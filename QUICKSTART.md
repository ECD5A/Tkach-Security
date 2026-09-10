# Tkach Security Quickstart

This is the shortest real API path for the current in-process Gateway. It is
not an SDK and it does not create a production transport. The compilable Basic
example is [examples/quickstart.rs](<C:\Users\stelm\Desktop\Tkach Security\crates\tkach-gateway\examples\quickstart.rs>).

Run it offline:

```text
cargo run -p tkach-gateway --example quickstart --locked
```

The example performs these real steps:

1. create typed `Destination`, `FlowRule`, `Ruslo`, `Policy`, `Krosna`, and
   bounded `Zaslon` values;
2. construct `Gateway` with a `ProtectedExecutor` implementation;
3. construct bounded `ExternalRequest` DATA;
4. invoke a deterministic provider through the staging boundary;
5. release output only from a successful `GatewayResult`.

## Deployment profile paths

| Profile | Additional integration | Resulting boundary |
| --- | --- | --- |
| Basic | trusted Krosna/Ruslo/Zaslon and non-effect/rejecting executor | bounded input/provider/output proof without real effects |
| Controlled | typed `PolicyRule` action grants, separate `FlowRule` destination policy, and a `ProtectedExecutor` that accepts only `Propusk` | authorized reads/writes and tool follow-up with exact scope |
| Sealed | Controlled plus `SecretHandle`/`SecretBroker`, exact `secret.use` rule, no raw credential/out-of-band path | broker-held secret use without model-visible raw secret |

The complete executable Controlled/Sealed examples and paired hostile variants
are in [product_proof.rs](<C:\Users\stelm\Desktop\Tkach Security\crates\tkach-gateway\tests\product_proof.rs>).

## Policy ergonomics

The common safe operation has explicit but small ceremony:

1. one typed action `PolicyRule::allow` for the exact operation/capability/
   resource/destination;
2. one separate directional `FlowRule::allow` for the information path;
3. one `ProtectedExecutor` boundary that receives only `Propusk`;
4. one final Gateway release destination.

Secret use adds one exact broker route and one opaque handle. There is no
blanket `filesystem = true`, public-export shortcut, policy DSL, magic default,
or model-controlled tool registration. Default-deny is visible in the typed
constructors, and denial evidence is available from `GatewayError::kind()` and
payload-free Sled trace.

## Developer rules

- Imported documents and tool output are `ExternalRole::Data` unless the host
  has a separate trusted reason to classify them otherwise.
- Never expose an executor, broker, raw `ActionRequest`, or raw secret to a
  provider.
- Configure action authorization and information flow separately.
- Return `GatewayResult::output()` only after `Gateway::run` succeeds.
- Use the Product Proof harness before changing policy/API semantics.

The example is intentionally Basic. It does not claim production readiness,
transaction rollback, semantic prompt-injection detection, or a real
executor.
