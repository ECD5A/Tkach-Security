# Dependency Review

This review covers the workspace runtime manifests and the excluded fuzz
harness. Dependency removal is accepted only when it reduces attack surface or
maintenance without weakening a security boundary.

| Dependency | Used by | Why it exists | TCB/attack-surface assessment | Decision |
| --- | --- | --- | --- | --- |
| `serde` | Core, Gateway, OpenAI | Validated typed wire/domain representations | Required at serialization boundaries; each boundary revalidates | Keep |
| `serde_json` | Core, Gateway, OpenAI, fuzz | Strict bounded JSON parsing/serialization and fixtures | Required; generic deserializers are preceded by byte/collection limits where needed | Keep |
| `thiserror` | Core, Gateway, OpenAI | Static structured error types | No payload-bearing provider errors; required for clear fail-closed classes | Keep |
| `reqwest` + `rustls-tls` | OpenAI | HTTPS transport with finite timeout and no redirects | Provider-specific boundary; rustls avoids platform-native TLS ambiguity in this adapter | Keep |
| `url` | OpenAI | HTTPS endpoint validation and trusted URL joining | Required to reject credentials, query, fragments, and ambiguous endpoints | Keep |
| `tkach-core` | Gateway/OpenAI | Typed security kernel and authority/flow state | Internal TCB dependency; required | Keep |
| `tkach-gateway` | OpenAI | Bounded lifecycle and provider staging boundary | Internal security boundary; required | Keep |
| `proptest` | Core dev only | Property tests for bounded security predicates | Test-only; not in runtime graph | Keep |
| `libfuzzer-sys` | Excluded fuzz harness | Fuzz target runtime | Tooling-only; excluded from workspace product graph | Keep outside product graph |

## Removed redundancy

The OpenAI crate declared `serde_json` both as a normal dependency and again as
a dev dependency. The dev declaration added no graph capability and was
removed; the normal declaration remains because production request/response
wire code uses it.

## Duplicate versions

`cargo deny check` still reports duplicate `syn` and `windows-sys` versions
through transitive procedural-macro and rustls/runtime paths. They are not
deduplicated with unsupported overrides: the versions have different upstream
requirements, and forcing convergence would enlarge supply-chain and build
risk. They remain a documented warning, not a silent policy exception.
