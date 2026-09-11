# Tkach Security
#
# Copyright 2026 ECD5A
# Licensed under the Apache License, Version 2.0.
#
# Repository: https://github.com/ECD5A/Tkach-Security
#
# See LICENSE and SECURITY.md.

"""Verify one version contract across Rust, SDK, and MCP metadata."""

from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path


class VersionContractError(ValueError):
    """A release-visible package version is inconsistent."""


_EXPECTED_CRATES = frozenset(
    {
        "tkach-core",
        "tkach-gateway",
        "tkach-http",
        "tkach-client",
        "tkach-mcp",
        "tkach-cli",
        "tkach-provider-openai",
    }
)


def _cargo_version(path: Path) -> str:
    with path.open("rb") as stream:
        return tomllib.load(stream)["package"]["version"]


def _version_sources(root: Path) -> dict[str, str]:
    sources = {
        path.parent.name: _cargo_version(path)
        for path in sorted((root / "crates").glob("*/Cargo.toml"))
    }
    with (root / "sdk/python/pyproject.toml").open("rb") as stream:
        sources["sdk/python"] = tomllib.load(stream)["project"]["version"]
    sources["sdk/javascript"] = json.loads(
        (root / "sdk/javascript/package.json").read_text(encoding="utf-8")
    )["version"]
    sources["server.json"] = json.loads(
        (root / "server.json").read_text(encoding="utf-8")
    )["version"]
    return sources


def check_version_contract(root: Path) -> str:
    """Return the shared version or fail when release metadata has drifted."""

    sources = _version_sources(root)
    missing = _EXPECTED_CRATES.difference(sources)
    if missing:
        missing_names = ", ".join(sorted(missing))
        raise VersionContractError(f"workspace package is missing: {missing_names}")
    if "tkach-core" not in sources or not sources["tkach-core"]:
        raise VersionContractError("tkach-core version is missing")
    expected = sources["tkach-core"]
    mismatches = {
        source: version for source, version in sources.items() if version != expected
    }
    if mismatches:
        details = ", ".join(
            f"{source}={version}" for source, version in sorted(mismatches.items())
        )
        raise VersionContractError(f"version contract mismatch: expected {expected}; {details}")
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).parents[2])
    args = parser.parse_args()
    version = check_version_contract(args.root.resolve())
    print(f"version contract passed: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
