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

## Strong Core Final Hardening Round 3

Targeted mutation scope covered the changed Sled evidence projection, Pechat
aggregate budget and redacted receipts, Niti wire decoder, Krosna broker-route
and unknown-resource gates, and Zaslon incremental matcher/pattern budget.

Initial Round 3 run:

```text
467 mutants tested: 299 caught, 139 unviable, 22 missed, 7 timeouts
```

The 22 initial misses were triaged. Non-equivalent misses were closed with
exhaustive projection, route, Debug, matcher-prefix, and exact-budget tests.
The final iterative rerun tested the remaining 9 mutants:

```text
9 mutants tested: 1 caught, 7 timeouts, 1 missed
```

The one final missed mutant is the known equivalent `Zaslon::empty()` change to
`Default::default()`; `Zaslon` derives `Default` and behavior is identical. The
seven timeouts weaken KMP loop guards and are killed by the bounded test timeout
rather than surviving to a passing result. No non-equivalent security-semantic
survivor remains unexplained.
