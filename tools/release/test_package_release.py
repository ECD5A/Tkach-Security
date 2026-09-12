# Tkach Security
#
# Copyright 2026 ECD5A
# Licensed under the Apache License, Version 2.0.
#
# Repository: https://github.com/ECD5A/Tkach-Security
#
# See LICENSE and SECURITY.md.

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

    def test_windows_zip_preserves_executable_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tkach.exe").write_bytes(b"windows-cli")
            (root / "tkach-mcp.exe").write_bytes(b"windows-mcp")
            specs = [
                f"tkach.exe={root / 'tkach.exe'}",
                f"tkach-mcp.exe={root / 'tkach-mcp.exe'}",
            ]
            archive_path = build_archive(
                "0.1.0",
                "x86_64-pc-windows-msvc",
                "zip",
                root / "out",
                specs,
                1_700_000_000,
            )
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.namelist(), [
                    "tkach-0.1.0-x86_64-pc-windows-msvc/tkach-mcp.exe",
                    "tkach-0.1.0-x86_64-pc-windows-msvc/tkach.exe",
                ])

    def test_windows_release_workflow_preserves_executable_extensions(self) -> None:
        workflow = (Path(__file__).parents[2] / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '--binary "tkach.exe=target/$env:TARGET/release/tkach.exe"',
            workflow,
        )
        self.assertIn(
            '--binary "tkach-mcp.exe=target/$env:TARGET/release/tkach-mcp.exe"',
            workflow,
        )

    def test_release_workflow_smokes_packaged_archives(self) -> None:
        workflow = (Path(__file__).parents[2] / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("- name: Smoke packaged Unix archive", workflow)
        self.assertIn('tar -xzf "release/${name}.tar.gz"', workflow)
        self.assertIn("- name: Smoke packaged Windows archive", workflow)
        self.assertIn(
            '([System.IO.Path]::Combine($extractDir, $name, "tkach.exe")) --version',
            workflow,
        )

    def test_oci_publication_is_release_gated_and_attested(self) -> None:
        root = Path(__file__).parents[2]
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        workflow = (root / ".github/workflows/publish-oci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('LABEL org.opencontainers.image.source="https://github.com/ECD5A/Tkach-Security"', dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("types: [published]", workflow)
        self.assertIn("environment: ghcr-publish", workflow)
        self.assertIn("packages: write", workflow)
        self.assertIn("platforms: linux/amd64,linux/arm64", workflow)
        self.assertIn("push-to-registry: true", workflow)
        self.assertNotIn("user/packages/container/tkach-security", workflow)
        self.assertNotIn("Set reviewed GHCR package visibility", workflow)
        self.assertNotIn(":latest", workflow)
        self.assertIn("docker/login-action@dbcb813823bdd20940b903addbd779551569679f", workflow)
        self.assertIn("docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a", workflow)

    def test_mcp_publication_validates_before_oidc_publish(self) -> None:
        workflow = (Path(__file__).parents[2] / ".github/workflows/publish-mcp.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("environment: mcp-publish", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("mcp-publisher_linux_amd64.tar.gz", workflow)
        self.assertIn("MCP_PUBLISHER_SHA256: a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc", workflow)
        validate_at = workflow.index(" validate server.json")
        login_at = workflow.index(" login github-oidc")
        publish_at = workflow.index(" publish server.json")
        self.assertLess(validate_at, login_at)
        self.assertLess(login_at, publish_at)

    def test_external_package_publication_is_gated_and_pinned(self) -> None:
        root = Path(__file__).parents[2]
        npm = (root / ".github/workflows/publish-npm.yml").read_text(encoding="utf-8")
        pypi = (root / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
        crates = (root / ".github/workflows/publish-crates.yml").read_text(encoding="utf-8")

        self.assertIn("types: [published]", npm)
        self.assertNotIn("  push:", npm)
        self.assertIn("ref: ${{ github.event.release.tag_name }}", npm)
        self.assertIn("id-token: write", npm)

        self.assertIn("types: [published]", pypi)
        self.assertIn("workflow_dispatch:", pypi)
        self.assertIn("github.event.release.tag_name || inputs.tag", pypi)
        self.assertIn("name: pypi-publish", pypi)
        self.assertIn("id-token: write", pypi)
        self.assertIn(
            "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
            pypi,
        )
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", pypi)
        self.assertIn("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", pypi)

        self.assertIn("workflow_dispatch:", crates)
        self.assertIn("environment: crates-publish", crates)
        self.assertIn("id-token: write", crates)
        self.assertIn(
            "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18",
            crates,
        )
        self.assertIn(
            "for crate in tkach-core tkach-gateway tkach-http tkach-client "
            "tkach-provider-openai tkach-mcp tkach-cli",
            crates,
        )
        self.assertIn("Package the root crate before authentication", crates)
        self.assertIn(
            'cargo +"${RUST_TOOLCHAIN}" package --package "${crate}" --locked',
            crates,
        )
        self.assertEqual(
            crates.count(
                '--user-agent "tkach-release/${version} '
                '(https://github.com/ECD5A/Tkach-Security)"'
            ),
            2,
        )
        self.assertLess(
            crates.index("Package the root crate before authentication"),
            crates.index("Authenticate with crates.io Trusted Publishing"),
        )
        self.assertLess(
            crates.index("Authenticate with crates.io Trusted Publishing"),
            crates.index(
                'cargo +"${RUST_TOOLCHAIN}" package --package "${crate}" --locked'
            ),
        )

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
