# Tkach Security
#
# Copyright 2026 ECD5A
# Licensed under the Apache License, Version 2.0.
#
# Repository: https://github.com/ECD5A/Tkach-Security
#
# See LICENSE and SECURITY.md.

from pathlib import Path
import unittest

from check_versions import VersionContractError, check_version_contract


class VersionContractTests(unittest.TestCase):
    def test_repository_versions_share_one_release_value(self) -> None:
        root = Path(__file__).parents[2]
        self.assertEqual(check_version_contract(root), "0.1.0")

    def test_missing_core_is_rejected(self) -> None:
        with self.assertRaises((FileNotFoundError, VersionContractError)):
            check_version_contract(Path(__file__).parent)


if __name__ == "__main__":
    unittest.main()
