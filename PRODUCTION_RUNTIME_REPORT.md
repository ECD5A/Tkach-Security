# Tkach Security Production Runtime Hardening v0.1

Historical production-runtime evidence only; this report is not an active
mandate. It records the evidence behind the `production-runtime-v0.1` tag.

### PRODUCTION RUNTIME STATUS

PASS on authoritative local evidence. This is a local production-runtime
candidate with explicit platform and deployment residuals. External Codex
Security scans are inconclusive and are not evidence.

### BASELINE

0b2887a93270dd3d5e93e31f3a41dc213cbde0bc, tagged production-boundary-v0.1.

### NEW HEAD

The final report/checkpoint commit, verified by the annotated local tag
production-runtime-v0.1. The exact SHA is recorded by the final tag and
worktree verification.

### THREAT MODEL

R0 is implemented in PRODUCTION_RUNTIME_THREAT_MODEL.md. The reviewed path is
Client -> bounded Transport -> Gateway -> Provider/Model staging ->
Krosna/Ruslo/Zaslon -> Propusk -> Tkach-owned Executor/Klyuchnik -> fixed
filesystem or loopback network effect -> safe release and receipt. Protected,
partial, and out-of-model claims are explicit.

### RUNTIME OWNERSHIP MODEL

R1 is implemented in RUNTIME_ISOLATION_MODEL.md. MODEL SIDE owns untrusted
bounded data and proposals; SECURITY RUNTIME owns authentication, lifecycle,
Gateway, primitives, limits, cancellation, and shutdown; EFFECT SIDE owns
Propusk-mediated OS handles and Klyuchnik; DEPLOYMENT CONTROL owns process,
ACL, TLS/IPC, and crash-dump policy. Provider and client code receive no
executor, broker, permit, raw handle, raw credential, or trusted constructor.

### FILESYSTEM HARDENING

RealEffectExecutor accepts only the exact fixed file bindings. Root, parent,
target, canonical containment, regular-file, create-only, bounded read/write,
sync/readback, and final path checks are enforced. Open operations use the
isolated no-follow adapter and no unsafe Rust.

### PLATFORM-SPECIFIC NO-FOLLOW / TOCTOU RESULTS

Unix uses O_NOFOLLOW and O_CLOEXEC. Windows uses
FILE_FLAG_OPEN_REPARSE_POINT through safe OpenOptions extensions and rejects
reparse metadata. Open-handle observations and path comparisons reject wrong
file identities where the platform exposes enough evidence. A universal
handle-relative parent transaction and stable Windows unique file-ID proof are
not claimed on this MSRV; the residual is documented and requires a reviewed
OS adapter or denial for hostile-concurrency deployment.

### FILESYSTEM EFFECT RESULTS

Actual isolated sandbox tests pass for bounded Confidential read and exact
create-only output write. Existing targets, links, junction parents, traversal,
normalization, wrong siblings, wrong destinations, and mutated action shapes
fail before the corresponding effect. Runtime E2E proves an authenticated
frame can commit the exact write once and replay cannot repeat it.

### NETWORK EFFECT RESULTS

The only real network effect is a fixed HTTP/1.1 request to an explicitly
configured non-zero loopback SocketAddr. Exact receiver delivery passes.
Unauthorized, protected, mutated, non-loopback, malformed, non-2xx, oversized,
timeout, write, shutdown, and partial-response cases are covered; no-connect
denials remain zero receiver connections.

### TRANSPORT ARCHITECTURE

RuntimeListener is a sequential loopback-only carrier with a four-byte
big-endian length prefix, a strict JSON frame, bounded allocation, 500 ms
read/write timeouts, and bounded response serialization. It has no compression,
redirect, proxy, generic headers, raw executor route, or worker queue. It is a
local frame boundary, not TLS or a public internet gateway.

### AUTHENTICATION RESULTS

RuntimeAuthenticator accepts only a trusted non-empty bounded proof and uses a
constant-time comparison over the bounded values. Missing, malformed,
oversized, invalid, and non-token identity inputs fail closed without Gateway,
provider, or effect admission. The proof is private and redacted; no
zeroization claim is made for authenticator storage.

### AUTHORIZATION SEPARATION

Authenticated caller identity is not the model principal and does not mint
Propusk. Every provider action still passes the ordinary Krosna/Ruslo/Zaslon
and Propusk path. Valid authentication with no action permit is denied and the
real filesystem remains unchanged.

### OUTCOMEUNKNOWN SEMANTICS

Pre-effect validation/connect failures map to FAILED_BEFORE_EFFECT. Failures
after an effect may have begun map to OUTCOME_UNKNOWN with uncertain=true.
Unknown is terminal, payload-free, never converted to success, and never an
automatic retry instruction. Response-encoding overflow preserves the bounded
effect receipt in a terminal ResponseTooLarge response.

### RETRY / IDEMPOTENCY RESULTS

Request and lifecycle IDs are bounded, token-shaped, consumed in an in-memory
per-instance ledger, and rejected on duplicate/replay. The runtime provides no
generic retry and does not claim durable cross-restart or distributed
exactly-once semantics. Network effects are not retried without an explicit
external idempotency proof.

### CANCELLATION RESULTS

Cancellation is sticky and checked before lifecycle/provider work, after
provider work, before staging/authorization, before execution, and before each
executor call. Blocking synchronous provider and OS calls cannot be
forcefully interrupted; their resulting state remains explicit and is not
silently retried.

### SHUTDOWN RESULTS

shutdown stops new admission. The sequential listener and service have no
unbounded drain queue; accepted in-flight work follows its existing synchronous
path, and no new lifecycle is admitted after the barrier. Post-barrier
acceptance returns ShuttingDown.

### CONCURRENCY / RESOURCE LIMITS

Runtime frame is capped at 64 KiB, response at 128 KiB, authentication at 256
bytes, IDs at 128 bytes, replay identities at 1,024 per category, and active
requests default to one. Existing Gateway limits cover messages, metadata,
provider chunks/turns, model context/output, tool results, effects, traces,
receipts, and error surfaces. The listener is one-connection-at-a-time.

### KLYUCHNIK OPERATIONAL RESULTS

SecretValue is private, has no operational Clone/Debug/Display/serde surface,
and zeroizes its owned bytes on Drop through zeroize. Klyuchnik returns opaque
handles and bounded broker receipts only. Host memory, core dumps, caller
copies, and separately exposed deployment secrets are not protected by this
claim.

### RUSLO RESULTS

Ruslo remains independent directional flow enforcement. Public network effect
requires trusted Public ingress, explicit Export, and ordinary action policy.
Runtime authentication does not alter source, classification, destination, or
flow direction, and cannot bypass Ruslo.

### OUT-OF-BAND BYPASS MODEL

The API makes provider/client-to-executor bypass difficult by type ownership:
only Gateway-held code receives the executor and only Propusk is accepted.
This is not a host-wide magical isolation claim. A same-process or same-privilege
integrator can open a separate file/socket path; such a path invalidates the
claim for that effect and is outside Tkach accounting.

### EFFECT RECEIPTS

Receipts contain bounded request/lifecycle identity, operation, resource kind,
destination, execution sequence, outcome, and uncertainty. They never contain
resource IDs where that would expose sensitive naming, payloads, prompts,
network bodies, credentials, permits, or raw secrets. Receipts are evidence,
not authority and not retry permission.

### HOSTILE RUNTIME RESULTS

Invalid authentication, malformed nested request, replayed IDs, cancellation,
shutdown, oversized frame, non-loopback bind, valid-auth unauthorized action,
response oversize, local receiver faults, and real sandbox mutations are
covered. Runtime E2E commits one exact real write only through authenticated
Gateway/Krosna/Propusk and rejects the same lifecycle replay.

### FALSE ALLOWS

No defined false allow was found in the Product Proof attack matrix or the
production-runtime hostile tests. Unauthorized real network variants produced
zero receiver connections; unauthorized runtime file write produced no target.

### FALSE DENIES

No defined false deny was found in the legitimate Product Proof workload or
the authorized real filesystem/network paths. Exact budget boundaries remain
accepted where the contract says they are accepted.

### FAULT-INJECTION RESULTS

Injected filesystem write/flush/read-boundary faults and network write,
flush, timeout, non-2xx, malformed, oversized, and post-connect faults map to
the explicit failure contract. No fault path adds an automatic retry or cleanup
against an uncertain path.

### MUTATION / PROPERTY RESULTS

Core property and independent-oracle suites pass. Final targeted runtime
mutation tested 110 mutants: 85 caught, 24 unviable because of platform or
conditional compilation, and one missed diagnostic-only Visitor::expecting
replacement. No security-path mutant survived. A broader pre-hardening Gateway
mutation run is retained as exploratory evidence and was manually reviewed;
the final targeted runtime result is authoritative for changed runtime code.

### PERFORMANCE / DOS RESULTS

The runtime has fixed input/output/auth/identity/replay/active-request bounds,
bounded nested parsing, no worker queue, sequential transport, bounded
timeouts, and bounded Gateway provider/effect/context/trace state. Performance
observations are local measurements, not an SLA or a proof against a
fully-compromised host.

### FULL TEST MATRIX

PASS:

- cargo fmt --all -- --check
- cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
- cargo test --workspace --all-targets --all-features --locked
- cargo test --workspace --release --all-targets --all-features --locked
- cargo test --workspace --doc --all-features --locked
- cargo doc --workspace --all-features --no-deps --locked with warnings denied
- cargo metadata --format-version=1 --locked --no-deps
- cargo audit --no-fetch
- cargo deny check
- cargo check --manifest-path fuzz/Cargo.toml --bins --locked --offline
- cargo package --workspace --allow-dirty --no-verify --offline
- cargo run -p tkach-gateway --example quickstart --locked

Fuzz binaries compile; libFuzzer execution is unavailable under the installed
Windows MSVC linker and is not claimed as executed.

### DEFECTS FOUND AND FIXED

- Replaced unstable Windows metadata APIs with a stable safe adapter and an
  explicit non-identity-proof residual.
- Corrected exact over-limit filesystem read semantics to OUTCOME_UNKNOWN.
- Added Klyuchnik SecretValue zeroization on Drop.
- Added bounded authenticated RuntimeService and loopback RuntimeListener.
- Replaced nested serde_json::Value materialization with RawValue so auth
  precedes nested Gateway request decoding.
- Added deterministic file identity, replay capacity, exact-boundary, hostile
  runtime E2E, and receipt-preserving response overflow regressions.
- Refreshed tracked fuzz lock dependencies for zeroize and target-specific libc.

### EXTERNAL SECURITY SCAN STATUS

Codex Security scans: INCONCLUSIVE / unavailable due to stalled external tooling; not used as security evidence.

Handles b8e5aaa2-ae7b-4f05-bf06-8b348bdc59d9 (threat_model) and
7d49ba8c-611f-4e4b-8bfc-fffc77df95f4 (preflight) remain running without
terminal artifacts. They are not PASS, were not canceled, and no new scan was
started.

### COMMITS

75ebde2, 84da829, 3ab1cfb, a7417aa, e3d1e50, 8fd19a0, 2eeff91, 5a4a7b7,
dc8ef8a, b1295e2, 0b8752d, and 00ae831 are the production-runtime
implementation, test, documentation, and lock-refresh stages. The final
checkpoint/report commit is the last local stage before the tag.

### TAG

Annotated local tag: production-runtime-v0.1. No git push was performed.

### WORKTREE

Final worktree is required to be clean. Generated fuzz/target and mutation
output directories are removed; tracked fuzz/Cargo.lock is retained. Literal
%TEMP% is absent and no creator reference exists.

### PROVEN CLAIMS

The local Rust API and fixed reference effects enforce bounded authentication,
identity, lifecycle, Krosna/Ruslo/Zaslon authorization, Propusk-only execution,
safe receipts, fixed loopback transport, create-only sandbox write, bounded
read, explicit outcome uncertainty, cancellation/shutdown admission, and
redacted operational surfaces under the tested deployment assumptions.

### UNPROVEN / PARTIALLY PROVEN AREAS

Universal parent-relative no-follow filesystem transactions, unique Windows
handle identity on this MSRV, forceful interruption of synchronous calls,
durable replay, distributed exactly-once effects, TLS, OS/process isolation,
core-dump protection, host-wide out-of-band prevention, live provider behavior,
and libFuzzer execution on this Windows host are not proven.

### REMAINING PRODUCT / SECURITY RISKS

Deployment must provide trusted authentication configuration, TLS or reviewed
IPC when leaving loopback, OS ACL/process/job isolation, secret injection and
core-dump policy, durable replay when required, and a reviewed platform
filesystem adapter for hostile concurrent mutation. A compromised host or
same-privilege bypass invalidates the corresponding claim.

### RECOMMENDED NEXT MACRO-PHASE

STOP at production-runtime-v0.1. A future phase may separately review sealed
process/OS isolation, authenticated IPC/TLS carrier, durable replay, and
platform-native handle-relative filesystem adapters. No OpenAI, Anthropic,
MCP, SDK, UI, cloud, browser, or new provider work is authorized by this
phase.
