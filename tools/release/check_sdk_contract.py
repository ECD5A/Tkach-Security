"""Check that every local SDK carrier keeps the shared contract surface.

This is a drift guard, not a substitute for the language-native tests. The
actual policy and protocol implementation remains in Rust; this script only
requires each adapter to expose the same typed result and bounded regression
cases before a release can proceed.
"""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]


REQUIRED = {
    "rust client implementation": (
        ROOT / "crates/tkach-client/src/lib.rs",
        ("pub enum ResponseKind", "pub fn kind(&self)", "CLIENT_IO_TIMEOUT"),
    ),
    "rust client regressions": (
        ROOT / "crates/tkach-client/src/lib.rs",
        (
            "run_accepts_a_bounded_slow_response_without_retry",
            "response_parser_rejects_chunked_and_oversized_responses",
            "response_kind_distinguishes_terminal_runtime_outcomes_without_retry",
        ),
    ),
    "python carrier": (
        ROOT / "sdk/python/tkach_client.py",
        ("class ResponseKind", "def kind", "HTTP_TIMEOUT_SECONDS"),
    ),
    "python regressions": (
        ROOT / "sdk/python/test_tkach_client.py",
        (
            "test_run_accepts_a_bounded_slow_response_without_retry",
            "test_invalid_response_fails_closed_without_retry",
            "test_response_kind_distinguishes_terminal_runtime_outcomes",
        ),
    ),
    "javascript carrier": (
        ROOT / "sdk/javascript/tkach_client.mjs",
        ("export const ResponseKind", "get kind()", "HTTP_TIMEOUT_MS"),
    ),
    "javascript regressions": (
        ROOT / "sdk/javascript/test_tkach_client.mjs",
        (
            "run accepts a bounded slow response without retry",
            "chunked and duplicate response framing fail closed",
            "response kind distinguishes terminal runtime outcomes",
        ),
    ),
    "go carrier": (
        ROOT / "sdk/go/tkachclient/client.go",
        ("type ResponseKind string", "func (r Response) Kind()", "clientTimeout"),
    ),
    "go regressions": (
        ROOT / "sdk/go/tkachclient/client_test.go",
        (
            "TestRunAcceptsABoundedSlowResponseWithoutRetry",
            "TestResponseFramingAndTransportFailuresFailClosed",
            "TestResponseKindDistinguishesTerminalRuntimeOutcomes",
        ),
    ),
    "mcp typed result": (
        ROOT / "crates/tkach-mcp/src/lib.rs",
        ("tkachOutcome", "lifecycle_lists_one_tool_and_delegates_one_bounded_call"),
    ),
}


def main() -> int:
    missing: list[str] = []
    for label, (path, needles) in REQUIRED.items():
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                missing.append(f"{label}: {path.relative_to(ROOT)} lacks {needle!r}")
    if missing:
        print("SDK contract drift detected:", file=sys.stderr)
        print("\n".join(f"- {item}" for item in missing), file=sys.stderr)
        return 1
    print(f"SDK contract passed: {len(REQUIRED)} carrier/regression surfaces checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
