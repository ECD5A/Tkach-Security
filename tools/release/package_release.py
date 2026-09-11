"""Create deterministic Tkach release archives.

The helper packages already-built binaries only. It does not build code,
resolve dependencies, or publish anything. Archive member names, ordering,
timestamps, ownership, and executable modes are fixed so the same inputs and
source epoch produce identical tar.gz/zip bytes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import io
import re
import stat
import tarfile
import zipfile
from pathlib import Path


_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_ZIP_EPOCH = 315532800  # 1980-01-01T00:00:00Z, ZIP's minimum timestamp.


class ReleasePackageError(ValueError):
    """A release input would make the archive ambiguous or unsafe."""


def _component(value: str, label: str) -> str:
    if not value or not _SAFE_COMPONENT.fullmatch(value):
        raise ReleasePackageError(f"invalid {label}")
    return value


def parse_binary_spec(spec: str) -> tuple[str, Path]:
    """Parse the CLI's ``archive-name=source-path`` binary specification."""

    name, separator, source = spec.partition("=")
    if not separator or not source:
        raise ReleasePackageError("binary must use name=source-path")
    return _component(name, "binary name"), Path(source)


def _read_binaries(specs: list[str]) -> list[tuple[str, bytes]]:
    if not specs:
        raise ReleasePackageError("at least one binary is required")
    members: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for spec in specs:
        name, source = parse_binary_spec(spec)
        if name in seen:
            raise ReleasePackageError("duplicate binary name")
        if source.is_symlink() or not source.is_file():
            raise ReleasePackageError(f"binary source is not a regular file: {source}")
        seen.add(name)
        members.append((name, source.read_bytes()))
    return sorted(members)


def _archive_root(version: str, target: str) -> str:
    return f"tkach-{_component(version, 'version')}-{_component(target, 'target')}"


def _tar_bytes(root: str, members: list[tuple[str, bytes]], epoch: int) -> bytes:
    uncompressed = io.BytesIO()
    with tarfile.open(fileobj=uncompressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in members:
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(payload)
            info.mtime = epoch
            info.mode = 0o755
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(payload))

    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=epoch, compresslevel=9) as stream:
        stream.write(uncompressed.getvalue())
    return compressed.getvalue()


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    return dt.datetime.fromtimestamp(max(epoch, _ZIP_EPOCH), dt.timezone.utc).timetuple()[:6]


def _zip_bytes(root: str, members: list[tuple[str, bytes]], epoch: int) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, payload in members:
            info = zipfile.ZipInfo(f"{root}/{name}", date_time=_zip_datetime(epoch))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = stat.S_IFREG | 0o755
            info.external_attr <<= 16
            archive.writestr(info, payload)
    return output.getvalue()


def build_archive(
    version: str,
    target: str,
    archive_format: str,
    output_dir: Path,
    binary_specs: list[str],
    source_date_epoch: int,
) -> Path:
    """Build one archive without overwriting an existing output."""

    if source_date_epoch < 0:
        raise ReleasePackageError("source date epoch must be non-negative")
    root = _archive_root(version, target)
    members = _read_binaries(binary_specs)
    if archive_format == "tar.gz":
        suffix = ".tar.gz"
        content = _tar_bytes(root, members, source_date_epoch)
    elif archive_format == "zip":
        suffix = ".zip"
        content = _zip_bytes(root, members, source_date_epoch)
    else:
        raise ReleasePackageError("archive format must be tar.gz or zip")

    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / f"{root}{suffix}"
    try:
        with destination.open("xb") as stream:
            stream.write(content)
    except FileExistsError as exc:
        raise ReleasePackageError(f"refusing to overwrite {destination}") from exc
    return destination


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--format", dest="archive_format", required=True, choices=("tar.gz", "zip"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--binary", action="append", required=True, metavar="NAME=PATH")
    return parser


def main() -> int:
    args = _parser().parse_args()
    destination = build_archive(
        args.version,
        args.target,
        args.archive_format,
        args.output_dir,
        args.binary,
        args.source_date_epoch,
    )
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
