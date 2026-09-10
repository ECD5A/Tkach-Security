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

## Authenticated local runtime boundary

For an application that needs a local transport boundary, construct a
`RuntimeService` around the trusted `Gateway`, provider, and a deployment-held
`RuntimeAuthenticator`, then bind `RuntimeListener` to `127.0.0.1` or `::1`.
Frames are a four-byte big-endian length followed by bounded strict JSON with
`request_id`, `lifecycle_id`, `auth`, and a nested Gateway request. The listener
serves one connection at a time, authenticates before Gateway invocation, and
returns only bounded output plus payload-free receipts.

This is a local frame contract, not TLS or a public internet server. Use
reviewed deployment TLS/IPC, OS identity and ACL separation, core-dump policy,
and a durable replay store when those properties are required. The in-memory
ledger rejects duplicates only for one runtime instance and deliberately makes
an `OutcomeUnknown` lifecycle terminal.

## Deployment profile paths

| Profile | Additional integration | Resulting boundary |
| --- | --- | --- |
| Basic | trusted Krosna/Ruslo/Zaslon and non-effect/rejecting executor | bounded input/provider/output proof without real effects |
| Controlled | typed `PolicyRule` action grants, separate `FlowRule` destination policy, and a `ProtectedExecutor` that accepts only `Propusk` | authorized reads/writes and tool follow-up with exact scope |
| Sealed | Controlled plus `SecretHandle`/`SecretBroker`, exact `secret.use` rule, no raw credential/out-of-band path | broker-held secret use without model-visible raw secret |
| Local effects | Controlled plus `RealEffectExecutor` and trusted local configuration | exact sandbox file read/create-only write and explicit loopback HTTP effect |

The complete executable Controlled/Sealed examples and paired hostile variants
are in [product_proof.rs](<C:\Users\stelm\Desktop\Tkach Security\crates\tkach-gateway\tests\product_proof.rs>).
The same proof contains a three-turn coding-agent workflow, an internal/public
release pair, Klyuchnik misuse cases, a fully compromised provider chain, and
explicit terminal-denial/fresh-run continuation semantics.

## Real local effects

`RealEffectExecutor` is the current narrow production-boundary reference. Its
trusted constructor takes an existing ordinary sandbox directory and a
non-zero loopback `SocketAddr`. It exposes only these fixed bindings:

- read `workspace/input.txt` and return bounded `TaggedData<String>` with
  `Confidential` classification;
- create `workspace/output.txt` with the fixed trusted
  `REAL_FILE_WRITE_CONTENT` bytes; existing files are rejected and never
  overwritten;
- send the fixed `REAL_NETWORK_PAYLOAD` to `REAL_NETWORK_PATH` using HTTP/1.1
  on the configured loopback endpoint.

The model controls none of the OS path, endpoint, HTTP path, or effect payload.
The executor accepts only a kernel-issued `Propusk`; an explicit public send
also requires `Krosna::authorize_tagged_public_send`, a `Public` trusted-ingress
tag, and a matching Ruslo Export rule. Network failures after bytes may have
left the process are reported as unknown, not as success. The implementation
uses canonicalized path/link checks but does not claim to eliminate every
concurrent path-substitution race; see
[REAL_EFFECT_CONTRACT.md](<C:\Users\stelm\Desktop\Tkach Security\REAL_EFFECT_CONTRACT.md>).

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

The example is intentionally Basic. It does not claim generic production
readiness, transaction rollback, semantic prompt-injection detection, or
security against a fully compromised host/OS. The real local effect profile is
deliberately narrower than a general production executor.
