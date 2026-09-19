# Tkach Security
#
# Copyright 2026 ECD5A
# Licensed under the Apache License, Version 2.0.
#
# Repository: https://github.com/ECD5A/Tkach-Security
#
# See LICENSE and SECURITY.md.

import json
from pathlib import Path
import tempfile
import unittest

from check_versions import (
    VersionContractError,
    check_mcp_registry_contract,
    check_version_contract,
)


class VersionContractTests(unittest.TestCase):
    def test_repository_versions_share_one_release_value(self) -> None:
        root = Path(__file__).parents[2]
        self.assertEqual(check_version_contract(root), "0.1.2")

    def test_missing_core_is_rejected(self) -> None:
        with self.assertRaises((FileNotFoundError, VersionContractError)):
            check_version_contract(Path(__file__).parent)

    def test_mcp_registry_contract_matches_published_cargo_adapter(self) -> None:
        root = Path(__file__).parents[2]
        check_mcp_registry_contract(root, "0.1.2")

    def test_mcp_registry_contract_rejects_missing_ownership_marker(self) -> None:
        source_root = Path(__file__).parents[2]
        manifest = json.loads((source_root / "server.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.json").write_text(json.dumps(manifest), encoding="utf-8")
            readme = root / "crates/tkach-mcp/README.md"
            readme.parent.mkdir(parents=True)
            readme.write_text("Tkach MCP adapter", encoding="utf-8")
            with self.assertRaisesRegex(VersionContractError, "ownership marker"):
                check_mcp_registry_contract(root, "0.1.2")


if __name__ == "__main__":
    unittest.main()
