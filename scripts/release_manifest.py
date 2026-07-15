#!/usr/bin/env python3
"""Validate a Calcifer release bundle and write its canonical v1 manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import BinaryIO


MANIFEST_NAME = "calcifer-release-manifest-v1.json"
MANIFEST_SCHEMA = "calcifer-release-manifest-v1"
CHECKSUM_NAME = "SHA256SUMS"
REPOSITORY = "kazu-42/calcifer"
RELEASE_WORKFLOW = ".github/workflows/release.yml"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_CONTENT_BYTES = 512 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 16
MAX_TAR_STREAM_BYTES = (
    MAX_ARCHIVE_CONTENT_BYTES
    + (2 * tarfile.RECORDSIZE)
    + (2 * MAX_ARCHIVE_ENTRIES * tarfile.BLOCKSIZE)
)
GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
GZIP_TRAILER_BYTES = 8
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_DOS_TIME = 0
ZIP_DOS_DATE = 33
ZIP_CREATE_SYSTEM = 3
ZIP_CREATE_VERSION = 20
ZIP_EXTRACT_VERSION = 20
ZIP_FLAGS = 0

SEMVER_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
SOURCE_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")

TARGET_METADATA = {
    "aarch64-apple-darwin": {
        "architecture": "aarch64",
        "os": "macos",
        "libc": None,
        "format": "tar.gz",
        "binary": "calcifer",
        "runtime_requirements": [
            {"kind": "operating_system", "name": "macos"},
        ],
    },
    "aarch64-unknown-linux-gnu": {
        "architecture": "aarch64",
        "os": "linux",
        "libc": "glibc",
        "format": "tar.gz",
        "binary": "calcifer",
        "runtime_requirements": [
            {"kind": "operating_system", "name": "linux"},
            {"kind": "libc", "name": "glibc", "minimum_version": "2.35"},
        ],
    },
    "x86_64-apple-darwin": {
        "architecture": "x86_64",
        "os": "macos",
        "libc": None,
        "format": "tar.gz",
        "binary": "calcifer",
        "runtime_requirements": [
            {"kind": "operating_system", "name": "macos"},
        ],
    },
    "x86_64-pc-windows-msvc": {
        "architecture": "x86_64",
        "os": "windows",
        "libc": None,
        "format": "zip",
        "binary": "calcifer.exe",
        "runtime_requirements": [
            {"kind": "operating_system", "name": "windows"},
            {"kind": "abi", "name": "msvc"},
        ],
    },
    "x86_64-unknown-linux-gnu": {
        "architecture": "x86_64",
        "os": "linux",
        "libc": "glibc",
        "format": "tar.gz",
        "binary": "calcifer",
        "runtime_requirements": [
            {"kind": "operating_system", "name": "linux"},
            {"kind": "libc", "name": "glibc", "minimum_version": "2.35"},
        ],
    },
}
SUPPORTED_TARGETS = tuple(sorted(TARGET_METADATA))
RELEASE_DOCUMENTS = ("LICENSE", "README.md", "SECURITY.md")


def release_channel(version: str) -> str:
    match = SEMVER_PATTERN.fullmatch(version)
    if match is None:
        raise ValueError("invalid semantic version")
    prerelease = match.group(4)
    if prerelease is not None:
        for identifier in prerelease.split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                raise ValueError("invalid semantic version")
    return "preview" if prerelease is not None else "stable"


def archive_name(version: str, target: str) -> str:
    extension = ".zip" if TARGET_METADATA[target]["format"] == "zip" else ".tar.gz"
    return f"calcifer-v{version}-{target}{extension}"


def _read_and_hash_stream(
    stream: BinaryIO,
    *,
    limit: int | None = None,
    too_large: str = "release input is too large",
) -> tuple[str, int]:
    digest = hashlib.sha256()
    consumed = 0
    while chunk := stream.read(1024 * 1024):
        consumed += len(chunk)
        if limit is not None and consumed > limit:
            raise ValueError(too_large)
        digest.update(chunk)
    return digest.hexdigest(), consumed


def _sha256_stream(stream: BinaryIO, *, limit: int | None = None) -> str:
    return _read_and_hash_stream(
        stream,
        limit=limit,
        too_large="release binary is too large",
    )[0]


def _sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return _sha256_stream(source)


def _validate_archive_path(name: str) -> str:
    if "\\" in name:
        raise ValueError(f"unsafe archive path: {name}")
    normalized = name[:-1] if name.endswith("/") else name
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ValueError(f"unsafe archive path: {name}")
    return normalized


def _expected_archive_entries(version: str, target: str) -> tuple[str, set[str]]:
    prefix = f"calcifer-v{version}-{target}"
    binary_name = str(TARGET_METADATA[target]["binary"])
    expected = {
        prefix,
        f"{prefix}/{binary_name}",
        *(f"{prefix}/{document}" for document in RELEASE_DOCUMENTS),
    }
    return f"{prefix}/{binary_name}", expected


def _expected_archive_order(version: str, target: str) -> tuple[str, ...]:
    prefix = f"calcifer-v{version}-{target}"
    binary_name = str(TARGET_METADATA[target]["binary"])
    return (
        prefix,
        f"{prefix}/{binary_name}",
        *(f"{prefix}/{document}" for document in RELEASE_DOCUMENTS),
    )


def _expected_zip_order(version: str, target: str) -> tuple[str, ...]:
    order = _expected_archive_order(version, target)
    return (f"{order[0]}/", *order[1:])


def _expected_zip_external_attr(
    name: str,
    *,
    directory_name: str,
    binary_name: str,
) -> int:
    if name == directory_name:
        return ((stat.S_IFDIR | 0o755) << 16) | 0x10
    mode = 0o755 if name == binary_name else 0o644
    return (stat.S_IFREG | mode) << 16


def _expand_canonical_gzip(path: Path, expanded: BinaryIO) -> int:
    """Expand exactly one packager-format gzip member under the tar size bound."""

    with path.open("rb") as source:
        if source.read(len(GZIP_HEADER)) != GZIP_HEADER:
            raise ValueError("release tar archive has a noncanonical gzip header")

        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        pending = b""
        expanded_bytes = 0
        checksum = 0
        trailing = b""
        while not decompressor.eof:
            if not pending:
                pending = source.read(64 * 1024)
                if not pending:
                    raise ValueError("release tar archive is invalid")

            remaining = MAX_TAR_STREAM_BYTES - expanded_bytes
            chunk = decompressor.decompress(
                pending,
                min(1024 * 1024, remaining + 1),
            )
            pending = decompressor.unconsumed_tail
            if len(chunk) > remaining:
                raise ValueError("release archive expands beyond the size limit")
            if chunk:
                expanded.write(chunk)
                checksum = zlib.crc32(chunk, checksum)
                expanded_bytes += len(chunk)

            if decompressor.eof:
                probe_bytes = GZIP_TRAILER_BYTES + len(GZIP_HEADER[:3])
                trailing = decompressor.unused_data[:probe_bytes]
                if len(trailing) < probe_bytes:
                    trailing += source.read(probe_bytes - len(trailing))

        flushed = decompressor.flush()
        if flushed:
            remaining = MAX_TAR_STREAM_BYTES - expanded_bytes
            if len(flushed) > remaining:
                raise ValueError("release archive expands beyond the size limit")
            expanded.write(flushed)
            checksum = zlib.crc32(flushed, checksum)
            expanded_bytes += len(flushed)

    if len(trailing) > GZIP_TRAILER_BYTES:
        if trailing[GZIP_TRAILER_BYTES:].startswith(GZIP_HEADER[:3]):
            raise ValueError("release tar archive must contain exactly one gzip member")
        raise ValueError("release tar archive is invalid")
    if len(trailing) != GZIP_TRAILER_BYTES:
        raise ValueError("release tar archive is invalid")
    expected_checksum, expected_size = struct.unpack("<LL", trailing)
    if expected_checksum != checksum or expected_size != expanded_bytes:
        raise ValueError("release tar archive is invalid")
    return expanded_bytes


def _inspect_tar(path: Path, version: str, target: str) -> tuple[str, str]:
    binary_path, expected = _expected_archive_entries(version, target)
    expected_order = _expected_archive_order(version, target)
    expected_directory = binary_path.split("/", maxsplit=1)[0]
    try:
        with tempfile.TemporaryFile() as expanded:
            expanded_bytes = _expand_canonical_gzip(path, expanded)

            expanded.seek(0)
            archive = tarfile.open(fileobj=expanded, mode="r:")
            try:
                names: list[str] = []
                content_bytes = 0
                actual_content_bytes = 0
                binary_sha256 = None
                expected_offset = 0
                for index, member in enumerate(archive):
                    if index >= MAX_ARCHIVE_ENTRIES:
                        raise ValueError("release archive contains too many entries")
                    name = _validate_archive_path(member.name)
                    names.append(name)
                    if not member.isdir() and not member.isreg():
                        raise ValueError(
                            "release archives may contain only regular files and directories"
                        )
                    if name == expected_directory:
                        if not member.isdir():
                            raise ValueError(
                                "release archive layout does not match the release contract"
                            )
                        if member.size != 0:
                            raise ValueError("release archive directory entry must be empty")
                    elif not member.isreg():
                        raise ValueError(
                            "release archive layout does not match the release contract"
                        )

                    expected_mode = (
                        0o755 if name in (expected_directory, binary_path) else 0o644
                    )
                    expected_type = (
                        tarfile.DIRTYPE if name == expected_directory else tarfile.REGTYPE
                    )
                    if (
                        index >= len(expected_order)
                        or member.name != expected_order[index]
                        or member.type != expected_type
                        or member.mode != expected_mode
                        or member.uid != 0
                        or member.gid != 0
                        or member.uname != ""
                        or member.gname != ""
                        or member.mtime != 0
                        or member.linkname != ""
                        or member.devmajor != 0
                        or member.devminor != 0
                        or member.pax_headers
                        or member.offset != expected_offset
                        or member.offset_data != expected_offset + tarfile.BLOCKSIZE
                    ):
                        raise ValueError(
                            "release tar archive has noncanonical tar metadata"
                        )
                    if member.isreg():
                        if member.size < 0:
                            raise ValueError("release archive entry has an invalid size")
                        content_bytes += member.size
                        if content_bytes > MAX_ARCHIVE_CONTENT_BYTES:
                            raise ValueError("release archive expands beyond the size limit")
                        if name == binary_path and member.size > MAX_BINARY_BYTES:
                            raise ValueError("release binary is too large")

                        entry = archive.extractfile(member)
                        if entry is None:
                            raise ValueError("release archive entry could not be read")
                        with entry:
                            digest, actual_size = _read_and_hash_stream(
                                entry,
                                limit=member.size,
                                too_large="release archive entry exceeds its declared size",
                            )
                        if actual_size != member.size:
                            raise ValueError(
                                "release archive entry size does not match its payload"
                            )
                        actual_content_bytes += actual_size
                        if actual_content_bytes > MAX_ARCHIVE_CONTENT_BYTES:
                            raise ValueError("release archive expands beyond the size limit")
                        if name == binary_path:
                            binary_sha256 = digest

                    expected_offset = member.offset_data + (
                        (member.size + tarfile.BLOCKSIZE - 1)
                        // tarfile.BLOCKSIZE
                        * tarfile.BLOCKSIZE
                    )

                if len(names) != len(set(names)):
                    raise ValueError("release archive contains duplicate paths")
                if tuple(names) != expected_order or set(names) != expected:
                    raise ValueError(
                        "release tar archive has noncanonical tar metadata"
                    )

                if binary_sha256 is None:
                    raise ValueError("release binary could not be read")

                logical_end = archive.offset
            finally:
                archive.close()

            minimum_stream_end = logical_end + (2 * tarfile.BLOCKSIZE)
            expected_stream_bytes = (
                (minimum_stream_end + tarfile.RECORDSIZE - 1)
                // tarfile.RECORDSIZE
                * tarfile.RECORDSIZE
            )
            if expanded_bytes != expected_stream_bytes:
                raise ValueError("release tar archive has invalid trailing data")
            expanded.seek(logical_end)
            while trailing := expanded.read(1024 * 1024):
                if any(trailing):
                    raise ValueError("release tar archive has invalid trailing data")
    except (tarfile.TarError, EOFError, zlib.error) as error:
        raise ValueError("release tar archive is invalid") from error
    return binary_path, binary_sha256


def _validate_zip_container(path: Path) -> tuple[int, int]:
    archive_size = path.stat().st_size
    end_record_size = 22
    if archive_size < end_record_size:
        raise ValueError("release zip archive is invalid")
    with path.open("rb") as source:
        source.seek(archive_size - end_record_size)
        end_record = source.read(end_record_size)
    try:
        (
            signature,
            disk_number,
            directory_disk,
            disk_entries,
            total_entries,
            directory_size,
            directory_offset,
            comment_size,
        ) = struct.unpack("<4s4H2LH", end_record)
    except struct.error as error:
        raise ValueError("release zip archive is invalid") from error
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or directory_disk != 0
        or disk_entries != total_entries
        or comment_size != 0
        or total_entries == 0xFFFF
        or directory_size == 0xFFFFFFFF
        or directory_offset == 0xFFFFFFFF
        or directory_offset + directory_size != archive_size - end_record_size
    ):
        raise ValueError("release zip archive is invalid")
    return total_entries, directory_offset


def _validate_zip_local_layout(
    path: Path,
    members: list[zipfile.ZipInfo],
    directory_offset: int,
) -> None:
    """Require the exact contiguous local headers emitted by the packager."""

    cursor = 0
    try:
        with path.open("rb") as source:
            for member in members:
                if member.header_offset != cursor:
                    raise ValueError("release zip archive is invalid")
                source.seek(cursor)
                header = source.read(30)
                if len(header) != 30:
                    raise ValueError("release zip archive is invalid")
                (
                    signature,
                    extract_version,
                    flags,
                    compression,
                    modified_time,
                    modified_date,
                    crc32,
                    compressed_size,
                    uncompressed_size,
                    filename_size,
                    extra_size,
                ) = struct.unpack("<4s5H3L2H", header)
                if (
                    signature != b"PK\x03\x04"
                    or extract_version != ZIP_EXTRACT_VERSION
                    or flags != ZIP_FLAGS
                    or compression != zipfile.ZIP_DEFLATED
                    or modified_time != ZIP_DOS_TIME
                    or modified_date != ZIP_DOS_DATE
                    or crc32 != member.CRC
                    or compressed_size != member.compress_size
                    or uncompressed_size != member.file_size
                ):
                    raise ValueError(
                        "release zip archive has noncanonical ZIP metadata"
                    )

                filename = source.read(filename_size)
                extra = source.read(extra_size)
                if len(filename) != filename_size or len(extra) != extra_size:
                    raise ValueError("release zip archive is invalid")
                if filename != member.filename.encode("ascii") or extra:
                    raise ValueError(
                        "release zip archive has noncanonical ZIP metadata"
                    )

                cursor = source.tell() + member.compress_size
                if cursor > directory_offset:
                    raise ValueError("release zip archive is invalid")

            if cursor != directory_offset:
                raise ValueError("release zip archive is invalid")
    except (struct.error, UnicodeEncodeError) as error:
        raise ValueError("release zip archive is invalid") from error


def _validate_zip_central_metadata(
    members: list[zipfile.ZipInfo],
    *,
    version: str,
    target: str,
) -> None:
    expected_order = _expected_zip_order(version, target)
    binary_name = expected_order[1]
    directory_name = expected_order[0]
    if tuple(member.filename for member in members) != expected_order:
        raise ValueError("release zip archive has noncanonical ZIP metadata")

    for member in members:
        expected_external_attr = _expected_zip_external_attr(
            member.filename,
            directory_name=directory_name,
            binary_name=binary_name,
        )
        if (
            member.date_time != ZIP_TIMESTAMP
            or member.compress_type != zipfile.ZIP_DEFLATED
            or member.comment != b""
            or member.extra != b""
            or member.create_system != ZIP_CREATE_SYSTEM
            or member.create_version != ZIP_CREATE_VERSION
            or member.extract_version != ZIP_EXTRACT_VERSION
            or member.reserved != 0
            or member.flag_bits != ZIP_FLAGS
            or member.volume != 0
            or member.internal_attr != 0
            or member.external_attr != expected_external_attr
        ):
            raise ValueError("release zip archive has noncanonical ZIP metadata")


def _inspect_zip(path: Path, version: str, target: str) -> tuple[str, str]:
    binary_path, expected = _expected_archive_entries(version, target)
    expected_directory = binary_path.split("/", maxsplit=1)[0]
    expected_member_count, directory_offset = _validate_zip_container(path)
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) != expected_member_count:
                raise ValueError("release zip archive is invalid")
            if len(members) > MAX_ARCHIVE_ENTRIES:
                raise ValueError("release archive contains too many entries")
            names: list[str] = []
            content_bytes = 0
            actual_content_bytes = 0
            binary_sha256 = None
            for member in members:
                name = _validate_archive_path(member.filename)
                names.append(name)
                file_type = (member.external_attr >> 16) & 0o170000
                if file_type == stat.S_IFLNK:
                    raise ValueError(
                        "release archives may contain only regular files and directories"
                    )
                if member.is_dir():
                    if name != expected_directory or file_type not in (0, stat.S_IFDIR):
                        raise ValueError(
                            "release archive layout does not match the release contract"
                        )
                    if member.file_size != 0:
                        raise ValueError("release archive directory entry must be empty")
                elif file_type not in (0, stat.S_IFREG):
                    raise ValueError(
                        "release archives may contain only regular files and directories"
                    )
                if member.flag_bits & 0x1:
                    raise ValueError("encrypted release archive entries are not allowed")
                if not member.is_dir():
                    content_bytes += member.file_size
                    if content_bytes > MAX_ARCHIVE_CONTENT_BYTES:
                        raise ValueError("release archive expands beyond the size limit")
                    if name == binary_path and member.file_size > MAX_BINARY_BYTES:
                        raise ValueError("release binary is too large")

                with archive.open(member) as entry:
                    digest, actual_size = _read_and_hash_stream(
                        entry,
                        limit=member.file_size,
                        too_large="release archive entry exceeds its declared size",
                    )
                if actual_size != member.file_size:
                    raise ValueError(
                        "release archive entry size does not match its payload"
                    )
                actual_content_bytes += actual_size
                if actual_content_bytes > MAX_ARCHIVE_CONTENT_BYTES:
                    raise ValueError("release archive expands beyond the size limit")
                if name == binary_path:
                    binary_sha256 = digest

            if len(names) != len(set(names)):
                raise ValueError("release archive contains duplicate paths")
            if set(names) != expected:
                raise ValueError("release archive layout does not match the release contract")

            if binary_sha256 is None:
                raise ValueError("release binary could not be read")
            _validate_zip_central_metadata(
                members,
                version=version,
                target=target,
            )
            _validate_zip_local_layout(path, members, directory_offset)
    except (
        zipfile.BadZipFile,
        EOFError,
        NotImplementedError,
        RuntimeError,
        zlib.error,
    ) as error:
        raise ValueError("release zip archive is invalid") from error
    return binary_path, binary_sha256


def _target_descriptor(dist: Path, version: str, target: str) -> dict[str, object]:
    metadata = TARGET_METADATA[target]
    name = archive_name(version, target)
    archive_path = dist / name
    archive_size = archive_path.stat().st_size
    if archive_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"release archive is too large: {name}")

    if metadata["format"] == "zip":
        binary_path, binary_sha256 = _inspect_zip(archive_path, version, target)
    else:
        binary_path, binary_sha256 = _inspect_tar(archive_path, version, target)

    return {
        "target": target,
        "os": metadata["os"],
        "architecture": metadata["architecture"],
        "libc": metadata["libc"],
        "archive": {
            "name": name,
            "format": metadata["format"],
            "size": archive_size,
            "sha256": _sha256_file(archive_path),
        },
        "binary": {
            "path": binary_path,
            "sha256": binary_sha256,
        },
        "runtime_requirements": metadata["runtime_requirements"],
    }


def _build_manifest(
    *,
    dist: Path,
    version: str,
    source_commit: str,
    tag_ref_digest: str,
    metadata_names: frozenset[str],
) -> bytes:
    channel = release_channel(version)
    if SOURCE_COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise ValueError("source commit must be a lowercase 40-character Git SHA")
    if SOURCE_COMMIT_PATTERN.fullmatch(tag_ref_digest) is None:
        raise ValueError("tag ref digest must be a lowercase 40-character Git SHA")
    if dist.is_symlink() or not dist.is_dir():
        raise ValueError("release bundle directory must be a regular directory")
    dist = dist.resolve(strict=True)

    expected_names = {
        archive_name(version, target) for target in SUPPORTED_TARGETS
    }
    actual_names = {
        entry.name
        for entry in dist.iterdir()
        if entry.name not in metadata_names
    }
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        unexpected = sorted(actual_names - expected_names)
        raise ValueError(
            "release bundle does not match the target allowlist "
            f"(missing={missing}, unexpected={unexpected})"
        )
    for name in expected_names:
        path = dist / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"release archive must be a regular file: {name}")

    document = {
        "schema": MANIFEST_SCHEMA,
        "product": "calcifer",
        "repository": REPOSITORY,
        "version": version,
        "tag": f"v{version}",
        "source_commit": source_commit,
        "tag_ref_digest": tag_ref_digest,
        "release_channel": channel,
        "targets": [
            _target_descriptor(dist, version, target) for target in SUPPORTED_TARGETS
        ],
        "attestations": {
            "artifact": {
                "kind": "github_artifact_attestation",
                "job": "publish",
                "subjects": "release_assets",
                "workflow": RELEASE_WORKFLOW,
            },
            "immutable_release": {
                "kind": "github_release_attestation",
                "required": True,
            },
            "signer_workflow": {
                "repository": REPOSITORY,
                "workflow": RELEASE_WORKFLOW,
            },
        },
    }
    encoded = (
        json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise ValueError("release manifest exceeds the 64 KiB limit")
    return encoded


def build_manifest(
    *,
    dist: Path,
    version: str,
    source_commit: str,
    tag_ref_digest: str,
) -> bytes:
    """Return the canonical manifest after strictly validating every archive."""

    return _build_manifest(
        dist=dist,
        version=version,
        source_commit=source_commit,
        tag_ref_digest=tag_ref_digest,
        metadata_names=frozenset({MANIFEST_NAME}),
    )


def validate_manifest(
    *,
    dist: Path,
    version: str,
    source_commit: str,
    tag_ref_digest: str,
) -> bytes:
    """Rebuild and compare a published bundle manifest byte for byte."""

    if dist.is_symlink() or not dist.is_dir():
        raise ValueError("release bundle directory must be a regular directory")
    dist = dist.resolve(strict=True)
    manifest_path = dist / MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("release manifest must be a regular file")
    with manifest_path.open("rb") as source:
        actual = source.read(MAX_MANIFEST_BYTES + 1)
        if len(actual) > MAX_MANIFEST_BYTES or source.read(1):
            raise ValueError("release manifest exceeds the 64 KiB limit")

    expected = _build_manifest(
        dist=dist,
        version=version,
        source_commit=source_commit,
        tag_ref_digest=tag_ref_digest,
        metadata_names=frozenset({MANIFEST_NAME, CHECKSUM_NAME}),
    )
    if actual != expected:
        raise ValueError(
            "release manifest does not match the canonical archive descriptors"
        )
    return actual


def write_manifest(
    *,
    dist: Path,
    output: Path,
    version: str,
    source_commit: str,
    tag_ref_digest: str,
) -> Path:
    """Atomically write the canonical manifest inside the validated bundle."""

    if output.name != MANIFEST_NAME:
        raise ValueError(f"manifest output must be named {MANIFEST_NAME}")
    if output.is_symlink():
        raise ValueError("manifest output must not be a symbolic link")
    dist = dist.resolve(strict=True)
    if output.parent.resolve(strict=True) != dist:
        raise ValueError("manifest output must be inside the release bundle")
    encoded = build_manifest(
        dist=dist,
        version=version,
        source_commit=source_commit,
        tag_ref_digest=tag_ref_digest,
    )

    descriptor, temporary_name = tempfile.mkstemp(
        dir=dist,
        prefix=f".{MANIFEST_NAME}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(encoded)
            destination.flush()
            os.fsync(destination.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, output)
        if hasattr(os, "O_DIRECTORY"):
            directory_descriptor = os.open(dist, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--tag-ref-digest", required=True)
    arguments = parser.parse_args()

    try:
        output = write_manifest(
            dist=arguments.dist,
            output=arguments.output,
            version=arguments.version,
            source_commit=arguments.source_commit,
            tag_ref_digest=arguments.tag_ref_digest,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
