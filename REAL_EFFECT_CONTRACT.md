# Real Effect Boundary Contract

This document defines the intentionally narrow local reference executor added
after `integration-proof-v0.1`. It is a security contract, not a promise that
arbitrary application tools are safe.

## Authority and configuration

`RealEffectExecutor` implements the existing `ProtectedExecutor` trait and
accepts only a kernel-issued `Propusk`. Its constructor is trusted host code:

- the sandbox root must already exist, be an ordinary directory, and not be a
  symlink/reparse point;
- the network endpoint must be an explicit non-zero loopback `SocketAddr`;
- no DNS name, Internet address, shell, URL parser, redirect, or model-selected
  configuration is accepted.

The executor has no raw-secret route. The public network path and payload, and
the file-write bytes, are compile-time trusted bindings. A request can select
none of them.

## Fixed effects

| Propusk shape | Real effect | Success evidence |
| --- | --- | --- |
| `Read`, `file.read`, File `workspace/input.txt`, Model | bounded UTF-8 file read | `TaggedData<String>` with File provenance and `Confidential` classification |
| `Write`, `file.write`, File `workspace/output.txt`, Internal `storage` | create-only write of `REAL_FILE_WRITE_CONTENT` | receipt with monotonic executor sequence and `Committed` outcome |
| `NetworkSend`, `network.send`, Network `public-api`, `PublicExternal` | fixed HTTP/1.1 request to the configured loopback endpoint | receipt only after bounded 2xx response |

Any changed operation, capability, resource kind/identifier, destination,
principal, scope shape, or unsupported path fails before the corresponding
effect. Existing output is rejected; overwrite is not implemented.

## Filesystem safety

The root, parent, and target are checked with `symlink_metadata` and
canonicalization. Open operations additionally use an isolated platform
adapter: Unix requests set `O_NOFOLLOW|O_CLOEXEC`; Windows requests set
`FILE_FLAG_OPEN_REPARSE_POINT` through safe `OpenOptions` extensions. Links/reparse points, absolute paths, drive/prefix syntax,
backslashes, dot/parent components, missing parents, outside-root targets,
wrong siblings, and normalization lookalikes are rejected. The read result is
bounded by the Gateway tool-result limit. The write uses `create_new`, so a
pre-existing target cannot be overwritten atomically by this API. It verifies
the same open handle's bytes, length, and the final path state before issuing a
receipt.

An opened file is checked as an ordinary file and compared with the path
observation after use. On Windows the stable standard-library metadata API
does not expose a unique handle file-id on this MSRV, so that comparison is
defense-in-depth observation, not an identity proof. A separate reviewed
Win32 handle-identity/handle-relative adapter is still required for a sealed
hostile-concurrency profile.

The write is intentionally create-only rather than pretending to provide
rollback. A failure after target creation can leave a partial target and is
reported as `OutcomeUnknown`; operators must treat that state as requiring
inspection. No cleanup operation is allowed to follow an uncertain path
substitution, because cleanup itself could delete an attacker-replaced file.

## Loopback network safety

The request is a fixed `POST` with a fixed path, host, content length, and body.
The response is bounded and must be HTTP/1.0 or HTTP/1.1 with a 2xx status.
Connect failure is `FailedBeforeEffect`; write, shutdown, read, malformed
response, non-2xx response, oversized response, and timeout after connection
are `OutcomeUnknown`. A successful receipt therefore means that the local
receiver observed a successful response check, not that an arbitrary remote
transaction is reversible.

Public export is not inferred from an ordinary Gateway/model context. The
explicit `Krosna::authorize_tagged_public_send` route requires a trusted
ingress `TaggedData` with `Public` classification, an explicit Ruslo `Export`
allow, and an ordinary action-policy allow. Untrusted/protected metadata is
denied before a Propusk exists. The standard Gateway path remains conservative:
an untrusted model proposal cannot create a public network send.

## TOCTOU boundary

The implementation uses safe Rust and standard filesystem APIs. Unix final
component no-follow flags and Windows final reparse-point flags reduce the
portable attack surface, but parent-component traversal is not a universal
handle-relative transaction in this adapter. A concurrent attacker with write
access to the sandbox can still race a parent path between validation and use;
the implementation rechecks where possible and reports post-open uncertainty,
but it does not claim to eliminate that race. Deployments requiring
adversarial same-process filesystem mutation must add an OS-specific
handle-relative adapter with an independently reviewed contract or deny this
executor profile.

## Verification

The isolated `crates/tkach-gateway/tests/real_effects.rs` suite covers:

- actual sandbox read and create-only write through `Propusk`;
- Gateway dispatch of a real authorized write;
- wrong sibling, child, drive-like, symlink, parent, and existing-target cases;
- exact loopback request delivery and no-connect denied/mutated cases;
- explicit Public Ruslo authorization and conservative untrusted denial;
- non-2xx failure, timeout, bounded receipts, and payload-free diagnostics.

This contract does not add a provider, SDK, MCP, cloud integration, UI, or
production transport.
