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
_MCP_SERVER_NAME = "io.github.ECD5A/tkach-security"
_MCP_SCHEMA_URL = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
_MCP_REPOSITORY_URL = "https://github.com/ECD5A/Tkach-Security"


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


def check_mcp_registry_contract(root: Path, expected_version: str) -> None:
    """Fail when local MCP Registry metadata drifts from the Cargo adapter."""

    try:
        manifest = json.loads(
            (root / "server.json").read_text(encoding="utf-8")
        )
        packages = manifest["packages"]
        package = packages[0]
        transport = package["transport"]
        raw_variables = package["environmentVariables"]
        variables = {
            variable["name"]: variable for variable in raw_variables
        }
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise VersionContractError("MCP Registry manifest is malformed") from exc

    expected_manifest = {
        "$schema": _MCP_SCHEMA_URL,
        "name": _MCP_SERVER_NAME,
        "title": "Tkach Security",
        "version": expected_version,
        "repository": {
            "url": _MCP_REPOSITORY_URL,
            "source": "github",
        },
    }
    for key, value in expected_manifest.items():
        if manifest.get(key) != value:
            raise VersionContractError(f"MCP Registry manifest field drifted: {key}")

    if not isinstance(packages, list) or len(packages) != 1:
        raise VersionContractError("MCP Registry manifest must expose one package")
    if package.get("registryType") != "cargo":
        raise VersionContractError("MCP Registry package must use the cargo registry")
    if package.get("identifier") != "tkach-mcp":
        raise VersionContractError(
            "MCP Registry package identifier must be tkach-mcp"
        )
    if package.get("version") != expected_version:
        raise VersionContractError("MCP Registry package version drifted")
    if transport != {"type": "stdio"}:
        raise VersionContractError("MCP Registry transport must remain stdio")

    expected_variables = {"TKACH_HTTP_ADDR", "TKACH_BEARER_TOKEN"}
    if (
        len(variables) != len(raw_variables)
        or set(variables) != expected_variables
    ):
        raise VersionContractError("MCP Registry environment variable set drifted")
    address = variables["TKACH_HTTP_ADDR"]
    if (
        address.get("default") != "127.0.0.1:8080"
        or address.get("format") != "string"
        or address.get("isRequired") is not False
        or address.get("isSecret") is not False
    ):
        raise VersionContractError("MCP Registry loopback address contract drifted")
    token = variables["TKACH_BEARER_TOKEN"]
    if (
        token.get("format") != "string"
        or token.get("isRequired") is not True
        or token.get("isSecret") is not True
        or "default" in token
    ):
        raise VersionContractError("MCP Registry token contract drifted")

    marker = f"mcp-name: {_MCP_SERVER_NAME}"
    readme = (root / "crates/tkach-mcp/README.md").read_text(encoding="utf-8")
    if not any(
        marker in line and "<!--" not in line for line in readme.splitlines()
    ):
        raise VersionContractError("MCP Registry ownership marker is missing")


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
    check_mcp_registry_contract(root, expected)
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
