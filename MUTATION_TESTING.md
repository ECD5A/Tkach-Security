# Mutation Testing

## Strong Core Hardening Round 2

The mutation target was the provider-independent `tkach-core` package. Raw
cargo-mutants artifacts remain outside the repository under the local temporary
directory; this file records the reproducible result and the survivor review.

Command:

```text
cargo mutants --package tkach-core --jobs 1 --no-times
```

Final rerun after all oracle changes:

```text
426 mutants tested: 293 caught, 132 unviable, 1 missed
```

The one missed mutant was:

```text
crates/tkach-core/src/zaslon.rs:211
replace Zaslon::empty -> Self with Default::default()
```

This is equivalent: `Zaslon` derives `Default`, and `empty()` already returns
`Self::default()`. It cannot change authorization, content scanning, stream
state, evidence, or any observable output. It is retained as an explicit
equivalent survivor rather than distorting the implementation to satisfy the
mutator.

Earlier runs exposed meaningful survivors in bounded string `visit_str`,
`is_known_capability`, `SecretValue` debug redaction, and broker-route
conditions. Independent tests were added for those semantics and a complete
rerun caught them. Diagnostic `Visitor::expecting` survivors were also closed
with exact error-message assertions.

Mutation testing is a test-oracle signal, not a coverage percentage. The
remaining non-security equivalent survivor is documented above; no
security-semantic survivor remains unexplained.
