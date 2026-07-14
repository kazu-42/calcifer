#!/usr/bin/env python3
"""Create deterministic Calcifer release archives using only the standard library."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import re
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path


SUPPORTED_TARGETS = frozenset(
    {
        "aarch64-apple-darwin",
        "aarch64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu",
    }
)
VERSION_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
DOCUMENTS = ("LICENSE", "README.md", "SECURITY.md")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _validate_inputs(
    project_root: Path,
    binary: Path,
    target: str,
    version: str,
) -> None:
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"unsupported release target: {target}")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("invalid release version")
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("binary must be a regular file")
    if "windows" not in target and os.name != "nt" and not os.access(binary, os.X_OK):
        raise ValueError("binary is not executable")

    for name in DOCUMENTS:
        path = project_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"required release document is not a regular file: {name}")


def _entries(
    project_root: Path,
    binary: Path,
    target: str,
) -> list[tuple[str, bytes, int]]:
    binary_name = "calcifer.exe" if "windows" in target else "calcifer"
    entries = [(binary_name, binary.read_bytes(), 0o755)]
    entries.extend(
        (name, (project_root / name).read_bytes(), 0o644) for name in DOCUMENTS
    )
    return entries


def _configure_tar_info(info: tarfile.TarInfo, mode: int) -> None:
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0


def _write_tarball(
    destination: Path,
    prefix: str,
    entries: list[tuple[str, bytes, int]],
) -> None:
    with destination.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as archive:
                directory = tarfile.TarInfo(prefix)
                directory.type = tarfile.DIRTYPE
                _configure_tar_info(directory, 0o755)
                archive.addfile(directory)

                for name, contents, mode in entries:
                    info = tarfile.TarInfo(f"{prefix}/{name}")
                    info.size = len(contents)
                    _configure_tar_info(info, mode)
                    archive.addfile(info, io.BytesIO(contents))


def _zip_info(name: str, mode: int, *, directory: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
    info.create_system = 3
    file_type = stat.S_IFDIR if directory else stat.S_IFREG
    info.external_attr = (file_type | mode) << 16
    if directory:
        info.external_attr |= 0x10
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _write_zip(
    destination: Path,
    prefix: str,
    entries: list[tuple[str, bytes, int]],
) -> None:
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        archive.writestr(_zip_info(f"{prefix}/", 0o755, directory=True), b"")
        for name, contents, mode in entries:
            archive.writestr(_zip_info(f"{prefix}/{name}", mode), contents)


def build_archive(
    *,
    project_root: Path,
    binary: Path,
    output_dir: Path,
    target: str,
    version: str,
) -> Path:
    """Build one release archive and atomically place it in output_dir."""

    if binary.is_symlink():
        raise ValueError("binary must be a regular file")
    project_root = project_root.resolve(strict=True)
    binary = binary.resolve(strict=True)
    _validate_inputs(project_root, binary, target, version)

    output_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"calcifer-v{version}-{target}"
    extension = ".zip" if "windows" in target else ".tar.gz"
    destination = output_dir / f"{prefix}{extension}"
    entries = _entries(project_root, binary, target)

    descriptor, temporary_name = tempfile.mkstemp(
        dir=output_dir,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        if extension == ".zip":
            _write_zip(temporary, prefix, entries)
        else:
            _write_tarball(temporary, prefix, entries)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)

    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()

    try:
        archive = build_archive(
            project_root=arguments.project_root,
            binary=arguments.binary,
            output_dir=arguments.output_dir,
            target=arguments.target,
            version=arguments.version,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
