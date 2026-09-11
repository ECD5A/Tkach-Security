from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from package_release import ReleasePackageError, build_archive


class ReleasePackageTests(unittest.TestCase):
    def _sources(self, root: Path) -> list[str]:
        (root / "tkach").write_bytes(b"cli-binary")
        (root / "tkach-mcp").write_bytes(b"mcp-binary")
        return [f"tkach={root / 'tkach'}", f"tkach-mcp={root / 'tkach-mcp'}"]

    def test_tar_gz_is_byte_stable_and_has_fixed_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            specs = self._sources(root)
            first = build_archive("0.1.0", "test-target", "tar.gz", root / "one", specs, 1_700_000_000)
            second = build_archive("0.1.0", "test-target", "tar.gz", root / "two", specs, 1_700_000_000)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(fileobj=io.BytesIO(first.read_bytes()), mode="r:gz") as archive:
                self.assertEqual(archive.getnames(), [
                    "tkach-0.1.0-test-target/tkach",
                    "tkach-0.1.0-test-target/tkach-mcp",
                ])
                self.assertEqual(archive.extractfile(archive.getnames()[0]).read(), b"cli-binary")
                self.assertEqual(archive.getmember(archive.getnames()[0]).uid, 0)

    def test_zip_is_byte_stable_and_has_fixed_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            specs = self._sources(root)
            first = build_archive("0.1.0", "test-target", "zip", root / "one", specs, 1_700_000_000)
            second = build_archive("0.1.0", "test-target", "zip", root / "two", specs, 1_700_000_000)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.namelist(), [
                    "tkach-0.1.0-test-target/tkach",
                    "tkach-0.1.0-test-target/tkach-mcp",
                ])
                self.assertEqual(archive.read(archive.namelist()[1]), b"mcp-binary")

    def test_source_epoch_changes_archive_and_existing_output_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            specs = self._sources(root)
            first = build_archive("0.1.0", "test-target", "tar.gz", root / "one", specs, 1_700_000_000)
            second = build_archive("0.1.0", "test-target", "tar.gz", root / "two", specs, 1_700_000_001)
            self.assertNotEqual(first.read_bytes(), second.read_bytes())
            with self.assertRaises(ReleasePackageError):
                build_archive("0.1.0", "test-target", "tar.gz", root / "one", specs, 1_700_000_000)

    def test_unsafe_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            specs = self._sources(root)
            for version, target in (("../0.1.0", "target"), ("0.1.0", "../target")):
                with self.subTest(version=version, target=target), self.assertRaises(ReleasePackageError):
                    build_archive(version, target, "zip", root / "out", specs, 1_700_000_000)
            with self.assertRaises(ReleasePackageError):
                build_archive("0.1.0", "target", "zip", root / "out", [f"../bad={root / 'tkach'}"], 1_700_000_000)


if __name__ == "__main__":
    unittest.main()
