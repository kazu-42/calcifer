import copy
import gzip
import hashlib
import io
import json
import os
import stat
import struct
import tarfile
import tempfile
import unittest
import zipfile
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from scripts import package_release, release_manifest


TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
)


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.version = "0.1.0-alpha.4"
        self.source_commit = "0123456789abcdef0123456789abcdef01234567"
        self.tag_ref_digest = "89abcdef0123456789abcdef0123456789abcdef"

        for name, contents in (
            ("README.md", "read me\n"),
            ("LICENSE", "license\n"),
            ("SECURITY.md", "security\n"),
        ):
            (self.project / name).write_text(contents, encoding="utf-8")

        for target in TARGETS:
            binary = self.root / f"calcifer-{target}"
            binary.write_bytes(f"synthetic binary for {target}\n".encode())
            binary.chmod(0o755)
            package_release.build_archive(
                project_root=self.project,
                binary=binary,
                output_dir=self.dist,
                target=target,
                version="0.1.0-alpha.4",
            )

    def build_manifest(
        self,
        *,
        dist: Path,
        version: str,
        source_commit: str,
        tag_ref_digest: str | None = None,
    ) -> bytes:
        return release_manifest.build_manifest(
            dist=dist,
            version=version,
            source_commit=source_commit,
            tag_ref_digest=tag_ref_digest or self.tag_ref_digest,
        )

    def _windows_archive(self) -> Path:
        return next(self.dist.glob("*x86_64-pc-windows-msvc.zip"))

    def _linux_archive(self) -> Path:
        return next(self.dist.glob("*x86_64-unknown-linux-gnu.tar.gz"))

    def _assert_bundle_rejected(self, message: str) -> None:
        with self.assertRaisesRegex(ValueError, message):
            self.build_manifest(
                dist=self.dist,
                version=self.version,
                source_commit=self.source_commit,
            )

    def _rewrite_windows_zip(
        self,
        mutate: Callable[[zipfile.ZipInfo], None],
        *,
        order: tuple[int, ...] | None = None,
        compression: int | None = None,
    ) -> None:
        archive_path = self._windows_archive()
        with zipfile.ZipFile(archive_path) as source:
            entries = [
                (copy.copy(member), source.read(member))
                for member in source.infolist()
            ]
        if order is not None:
            entries = [entries[index] for index in order]

        encoded = io.BytesIO()
        with zipfile.ZipFile(encoded, "w") as destination:
            for member, contents in entries:
                if compression is not None:
                    member.compress_type = compression
                mutate(member)
                destination.writestr(member, contents)
        archive_path.write_bytes(encoded.getvalue())
        with zipfile.ZipFile(archive_path) as readable:
            self.assertIsNone(readable.testzip())

    @staticmethod
    def _zip_central_records(encoded: bytes) -> tuple[int, list[tuple[int, bytes]]]:
        end_record_offset = len(encoded) - 22
        signature, _, _, _, count, _, directory_offset, comment_size = (
            struct.unpack_from("<4s4H2LH", encoded, end_record_offset)
        )
        if signature != b"PK\x05\x06" or comment_size != 0:
            raise AssertionError("test fixture must use a comment-free classic ZIP")

        records = []
        cursor = directory_offset
        for _ in range(count):
            if encoded[cursor : cursor + 4] != b"PK\x01\x02":
                raise AssertionError("test fixture central directory is invalid")
            filename_size, extra_size, entry_comment_size = struct.unpack_from(
                "<HHH", encoded, cursor + 28
            )
            filename = encoded[cursor + 46 : cursor + 46 + filename_size]
            records.append((cursor, filename))
            cursor += 46 + filename_size + extra_size + entry_comment_size
        return directory_offset, records

    def _insert_zip_extra(self, *, central: bool) -> None:
        archive_path = self._windows_archive()
        encoded = bytearray(archive_path.read_bytes())
        directory_offset, records = self._zip_central_records(encoded)
        extra = b"\xfe\xca\x00\x00"

        if central:
            record_offset, _ = records[1]
            filename_size = struct.unpack_from("<H", encoded, record_offset + 28)[0]
            insertion_offset = record_offset + 46 + filename_size
            encoded[insertion_offset:insertion_offset] = extra
            struct.pack_into("<H", encoded, record_offset + 30, len(extra))
            end_record_offset = len(encoded) - 22
            directory_size = struct.unpack_from(
                "<L", encoded, end_record_offset + 12
            )[0]
            struct.pack_into(
                "<L", encoded, end_record_offset + 12, directory_size + len(extra)
            )
        else:
            with zipfile.ZipFile(archive_path) as source:
                member = source.infolist()[-1]
            local_offset = member.header_offset
            filename_size = struct.unpack_from("<H", encoded, local_offset + 26)[0]
            insertion_offset = local_offset + 30 + filename_size
            encoded[insertion_offset:insertion_offset] = extra
            struct.pack_into("<H", encoded, local_offset + 28, len(extra))
            end_record_offset = len(encoded) - 22
            struct.pack_into(
                "<L",
                encoded,
                end_record_offset + 16,
                directory_offset + len(extra),
            )

        archive_path.write_bytes(encoded)
        with zipfile.ZipFile(archive_path) as readable:
            self.assertIsNone(readable.testzip())

    def _patch_zip_binary_headers(
        self,
        *,
        local_offset: int,
        central_offset: int,
        value: int,
    ) -> None:
        archive_path = self._windows_archive()
        encoded = bytearray(archive_path.read_bytes())
        with zipfile.ZipFile(archive_path) as source:
            binary = source.infolist()[1]
        _, records = self._zip_central_records(encoded)
        record_offset, _ = records[1]
        struct.pack_into("<H", encoded, binary.header_offset + local_offset, value)
        struct.pack_into("<H", encoded, record_offset + central_offset, value)
        archive_path.write_bytes(encoded)
        with zipfile.ZipFile(archive_path) as readable:
            self.assertIsNone(readable.testzip())

    def _rewrite_linux_tar(
        self,
        mutate: Callable[[tarfile.TarInfo], None],
        *,
        order: tuple[int, ...] | None = None,
        tar_format: int = tarfile.USTAR_FORMAT,
    ) -> None:
        archive_path = self._linux_archive()
        with tarfile.open(archive_path, "r:gz") as source:
            entries = []
            for member in source:
                if member.isdir():
                    contents = b""
                else:
                    extracted = source.extractfile(member)
                    self.assertIsNotNone(extracted)
                    contents = extracted.read()
                entries.append((copy.copy(member), contents))
        if order is not None:
            entries = [entries[index] for index in order]

        with archive_path.open("wb") as raw:
            with gzip.GzipFile(
                fileobj=raw,
                mode="wb",
                filename="",
                mtime=0,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tar_format,
                ) as destination:
                    for member, contents in entries:
                        mutate(member)
                        if member.isdir():
                            destination.addfile(member)
                        else:
                            destination.addfile(member, io.BytesIO(contents))

    def _patch_tar_binary_numeric_field(self, offset: int, value: int) -> None:
        archive_path = self._linux_archive()
        expanded = bytearray(gzip.decompress(archive_path.read_bytes()))
        header_offset = tarfile.BLOCKSIZE
        expanded[header_offset + offset : header_offset + offset + 8] = (
            f"{value:07o}\0".encode("ascii")
        )
        checksum_offset = header_offset + 148
        expanded[checksum_offset : checksum_offset + 8] = b"        "
        checksum = sum(expanded[header_offset : header_offset + tarfile.BLOCKSIZE])
        expanded[checksum_offset : checksum_offset + 8] = (
            f"{checksum:06o}\0 ".encode("ascii")
        )

        encoded = io.BytesIO()
        with gzip.GzipFile(
            fileobj=encoded,
            mode="wb",
            filename="",
            mtime=0,
        ) as compressed:
            compressed.write(expanded)
        archive_path.write_bytes(encoded.getvalue())

    def test_builds_canonical_manifest_for_all_supported_targets(self) -> None:
        first = self.build_manifest(
            dist=self.dist,
            version="0.1.0-alpha.4",
            source_commit="0123456789abcdef0123456789abcdef01234567",
        )
        second = self.build_manifest(
            dist=self.dist,
            version="0.1.0-alpha.4",
            source_commit="0123456789abcdef0123456789abcdef01234567",
        )

        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertLessEqual(len(first), release_manifest.MAX_MANIFEST_BYTES)

        document = json.loads(first)
        self.assertEqual(document["schema"], "calcifer-release-manifest-v1")
        self.assertEqual(document["product"], "calcifer")
        self.assertEqual(document["repository"], "kazu-42/calcifer")
        self.assertEqual(document["version"], "0.1.0-alpha.4")
        self.assertEqual(document["tag"], "v0.1.0-alpha.4")
        self.assertEqual(document["tag_ref_digest"], self.tag_ref_digest)
        self.assertEqual(document["release_channel"], "preview")
        self.assertEqual(
            [target["target"] for target in document["targets"]],
            list(TARGETS),
        )

        linux = document["targets"][1]
        self.assertEqual(linux["os"], "linux")
        self.assertEqual(linux["architecture"], "aarch64")
        self.assertEqual(linux["libc"], "glibc")
        self.assertEqual(linux["archive"]["format"], "tar.gz")
        self.assertEqual(linux["archive"]["size"], (self.dist / linux["archive"]["name"]).stat().st_size)
        self.assertEqual(
            linux["archive"]["sha256"],
            hashlib.sha256((self.dist / linux["archive"]["name"]).read_bytes()).hexdigest(),
        )
        self.assertEqual(
            linux["binary"]["path"],
            "calcifer-v0.1.0-alpha.4-aarch64-unknown-linux-gnu/calcifer",
        )
        self.assertEqual(
            linux["binary"]["sha256"],
            hashlib.sha256(b"synthetic binary for aarch64-unknown-linux-gnu\n").hexdigest(),
        )
        self.assertEqual(
            document["attestations"]["artifact"]["workflow"],
            ".github/workflows/release.yml",
        )
        self.assertEqual(document["attestations"]["artifact"]["job"], "publish")
        self.assertTrue(document["attestations"]["immutable_release"]["required"])

    def test_writes_manifest_atomically_with_exact_canonical_bytes(self) -> None:
        destination = self.dist / release_manifest.MANIFEST_NAME

        written = release_manifest.write_manifest(
            dist=self.dist,
            output=destination,
            version="0.1.0-alpha.4",
            source_commit="0123456789abcdef0123456789abcdef01234567",
            tag_ref_digest=self.tag_ref_digest,
        )

        self.assertEqual(written, destination)
        self.assertEqual(
            destination.read_bytes(),
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            ),
        )
        self.assertEqual(
            [path.name for path in self.dist.iterdir() if path.name.startswith(".")],
            [],
        )

    def test_stable_version_selects_stable_channel(self) -> None:
        stable_dist = self.root / "stable-dist"
        stable_dist.mkdir()
        for target in TARGETS:
            binary = self.root / f"stable-{target}"
            binary.write_bytes(target.encode())
            binary.chmod(0o755)
            package_release.build_archive(
                project_root=self.project,
                binary=binary,
                output_dir=stable_dist,
                target=target,
                version="1.2.3",
            )

        document = json.loads(
            self.build_manifest(
                dist=stable_dist,
                version="1.2.3",
                source_commit="abcdef0123456789abcdef0123456789abcdef01",
            )
        )

        self.assertEqual(document["release_channel"], "stable")

    def test_rejects_missing_or_unexpected_bundle_entries(self) -> None:
        next(self.dist.glob("*aarch64-apple-darwin.tar.gz")).unlink()
        with self.assertRaisesRegex(ValueError, "release bundle does not match"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

        (self.dist / "unexpected.txt").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "release bundle does not match"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_archive_path_traversal(self) -> None:
        archive = next(self.dist.glob("*x86_64-unknown-linux-gnu.tar.gz"))
        with archive.open("wb") as raw:
            with gzip.GzipFile(
                fileobj=raw,
                mode="wb",
                filename="",
                mtime=0,
            ) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as malformed:
                    info = tarfile.TarInfo("../calcifer")
                    info.size = 0
                    malformed.addfile(info)

        with self.assertRaisesRegex(ValueError, "unsafe archive path"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_corrupt_unread_zip_entries(self) -> None:
        archive = next(self.dist.glob("*x86_64-pc-windows-msvc.zip"))
        prefix = "calcifer-v0.1.0-alpha.4-x86_64-pc-windows-msvc"
        document_path = f"{prefix}/README.md"

        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as malformed:
            directory = zipfile.ZipInfo(f"{prefix}/")
            directory.create_system = 3
            directory.external_attr = (stat.S_IFDIR | 0o755) << 16
            malformed.writestr(directory, b"")
            for name in ("calcifer.exe", "LICENSE", "README.md", "SECURITY.md"):
                member = zipfile.ZipInfo(f"{prefix}/{name}")
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | 0o644) << 16
                malformed.writestr(member, name.encode("ascii"))

        with zipfile.ZipFile(archive) as release_zip:
            member = release_zip.getinfo(document_path)
            header_offset = member.header_offset

        encoded = bytearray(archive.read_bytes())
        filename_length, extra_length = struct.unpack_from(
            "<HH",
            encoded,
            header_offset + 26,
        )
        payload_offset = header_offset + 30 + filename_length + extra_length
        encoded[payload_offset] ^= 1
        archive.write_bytes(encoded)

        with self.assertRaisesRegex(ValueError, "release zip archive is invalid"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_tar_gzip_trailing_garbage(self) -> None:
        archive = next(self.dist.glob("*x86_64-unknown-linux-gnu.tar.gz"))
        archive.write_bytes(archive.read_bytes() + b"not-a-valid-gzip-member")

        with self.assertRaisesRegex(ValueError, "release tar archive is invalid"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_nonempty_tar_directory_entries(self) -> None:
        archive = next(self.dist.glob("*aarch64-unknown-linux-gnu.tar.gz"))
        prefix = "calcifer-v0.1.0-alpha.4-aarch64-unknown-linux-gnu"
        with archive.open("wb") as raw:
            with gzip.GzipFile(
                fileobj=raw,
                mode="wb",
                filename="",
                mtime=0,
            ) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as malformed:
                    directory = tarfile.TarInfo(prefix)
                    directory.type = tarfile.DIRTYPE
                    directory.size = 1
                    malformed.addfile(directory, io.BytesIO(b"x"))
                    for name in ("calcifer", "LICENSE", "README.md", "SECURITY.md"):
                        contents = name.encode("ascii")
                        member = tarfile.TarInfo(f"{prefix}/{name}")
                        member.size = len(contents)
                        malformed.addfile(member, io.BytesIO(contents))

        with self.assertRaisesRegex(ValueError, "directory entry must be empty"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_nonempty_zip_directory_entries(self) -> None:
        archive = next(self.dist.glob("*x86_64-pc-windows-msvc.zip"))
        prefix = "calcifer-v0.1.0-alpha.4-x86_64-pc-windows-msvc"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as malformed:
            directory = zipfile.ZipInfo(f"{prefix}/")
            directory.create_system = 3
            directory.external_attr = (stat.S_IFDIR | 0o755) << 16
            malformed.writestr(directory, b"x")
            for name in ("calcifer.exe", "LICENSE", "README.md", "SECURITY.md"):
                member = zipfile.ZipInfo(f"{prefix}/{name}")
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | 0o644) << 16
                malformed.writestr(member, name.encode("ascii"))

        with self.assertRaisesRegex(ValueError, "directory entry must be empty"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_zip_trailing_bytes(self) -> None:
        archive = next(self.dist.glob("*x86_64-pc-windows-msvc.zip"))
        archive.write_bytes(archive.read_bytes() + b"trailing")

        with self.assertRaisesRegex(ValueError, "release zip archive is invalid"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_zip_leading_bytes_outside_the_local_header_stream(self) -> None:
        archive = next(self.dist.glob("*x86_64-pc-windows-msvc.zip"))
        prefix = b"synthetic-self-extracting-stub"
        encoded = bytearray(prefix + archive.read_bytes())
        end_record_offset = len(encoded) - 22
        (
            signature,
            _,
            _,
            _,
            total_entries,
            directory_size,
            original_directory_offset,
            _,
        ) = struct.unpack_from("<4s4H2LH", encoded, end_record_offset)
        self.assertEqual(signature, b"PK\x05\x06")

        directory_offset = original_directory_offset + len(prefix)
        struct.pack_into("<L", encoded, end_record_offset + 16, directory_offset)
        cursor = directory_offset
        for _ in range(total_entries):
            self.assertEqual(encoded[cursor : cursor + 4], b"PK\x01\x02")
            filename_size, extra_size, comment_size = struct.unpack_from(
                "<HHH", encoded, cursor + 28
            )
            local_header_offset = struct.unpack_from("<L", encoded, cursor + 42)[0]
            struct.pack_into(
                "<L",
                encoded,
                cursor + 42,
                local_header_offset + len(prefix),
            )
            cursor += 46 + filename_size + extra_size + comment_size
        self.assertEqual(cursor, directory_offset + directory_size)
        archive.write_bytes(encoded)
        with zipfile.ZipFile(archive) as readable:
            self.assertIsNone(readable.testzip())

        with self.assertRaisesRegex(ValueError, "release zip archive is invalid"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_zip_gap_before_the_central_directory(self) -> None:
        archive = next(self.dist.glob("*x86_64-pc-windows-msvc.zip"))
        original = archive.read_bytes()
        end_record_offset = len(original) - 22
        directory_offset = struct.unpack_from("<L", original, end_record_offset + 16)[0]
        gap = b"unowned-zip-bytes"
        encoded = bytearray(
            original[:directory_offset] + gap + original[directory_offset:]
        )
        struct.pack_into(
            "<L",
            encoded,
            len(encoded) - 22 + 16,
            directory_offset + len(gap),
        )
        archive.write_bytes(encoded)
        with zipfile.ZipFile(archive) as readable:
            self.assertIsNone(readable.testzip())

        with self.assertRaisesRegex(ValueError, "release zip archive is invalid"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_noncanonical_zip_entry_comments_and_extras(self) -> None:
        original = self._windows_archive().read_bytes()

        def add_comment(member: zipfile.ZipInfo) -> None:
            if member.filename.endswith("/calcifer.exe"):
                member.comment = b"noncanonical"

        cases = (
            ("central comment", lambda: self._rewrite_windows_zip(add_comment)),
            ("central extra", lambda: self._insert_zip_extra(central=True)),
            ("local extra", lambda: self._insert_zip_extra(central=False)),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                self._windows_archive().write_bytes(original)
                mutate()
                self._assert_bundle_rejected("canonical ZIP metadata")

    def test_rejects_noncanonical_zip_versions_flags_timestamp_and_modes(self) -> None:
        original = self._windows_archive().read_bytes()

        def mutate_binary(
            attribute: str,
            value: object,
        ) -> Callable[[zipfile.ZipInfo], None]:
            def apply(member: zipfile.ZipInfo) -> None:
                if member.filename.endswith("/calcifer.exe"):
                    setattr(member, attribute, value)

            return apply

        cases = (
            (
                "timestamp",
                lambda: self._rewrite_windows_zip(
                    mutate_binary("date_time", (1980, 1, 2, 0, 0, 0))
                ),
            ),
            (
                "creator system",
                lambda: self._rewrite_windows_zip(
                    mutate_binary("create_system", 0)
                ),
            ),
            (
                "creator version",
                lambda: self._rewrite_windows_zip(
                    mutate_binary("create_version", 21)
                ),
            ),
            (
                "extract version",
                lambda: self._patch_zip_binary_headers(
                    local_offset=4,
                    central_offset=6,
                    value=21,
                ),
            ),
            (
                "flags",
                lambda: self._patch_zip_binary_headers(
                    local_offset=6,
                    central_offset=8,
                    value=0x800,
                ),
            ),
            (
                "internal attributes",
                lambda: self._rewrite_windows_zip(
                    mutate_binary("internal_attr", 1)
                ),
            ),
            (
                "mode",
                lambda: self._rewrite_windows_zip(
                    mutate_binary(
                        "external_attr",
                        (stat.S_IFREG | 0o700) << 16,
                    )
                ),
            ),
            (
                "compression",
                lambda: self._rewrite_windows_zip(
                    lambda _: None,
                    compression=zipfile.ZIP_STORED,
                ),
            ),
            (
                "order",
                lambda: self._rewrite_windows_zip(
                    lambda _: None,
                    order=(0, 1, 3, 2, 4),
                ),
            ),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                self._windows_archive().write_bytes(original)
                mutate()
                self._assert_bundle_rejected("canonical ZIP metadata")

    def test_rejects_noncanonical_tar_entry_metadata_and_order(self) -> None:
        original = self._linux_archive().read_bytes()

        def mutate_binary(
            attribute: str,
            value: object,
        ) -> Callable[[tarfile.TarInfo], None]:
            def apply(member: tarfile.TarInfo) -> None:
                if member.name.endswith("/calcifer"):
                    setattr(member, attribute, value)

            return apply

        cases = (
            ("uid", mutate_binary("uid", 1), None, tarfile.USTAR_FORMAT),
            ("gid", mutate_binary("gid", 1), None, tarfile.USTAR_FORMAT),
            ("uname", mutate_binary("uname", "builder"), None, tarfile.USTAR_FORMAT),
            ("gname", mutate_binary("gname", "builder"), None, tarfile.USTAR_FORMAT),
            ("mtime", mutate_binary("mtime", 1), None, tarfile.USTAR_FORMAT),
            ("mode", mutate_binary("mode", 0o700), None, tarfile.USTAR_FORMAT),
            (
                "linkname",
                mutate_binary("linkname", "unused"),
                None,
                tarfile.USTAR_FORMAT,
            ),
            (
                "pax",
                mutate_binary("pax_headers", {"comment": "noncanonical"}),
                None,
                tarfile.PAX_FORMAT,
            ),
            (
                "order",
                lambda _: None,
                (0, 1, 3, 2, 4),
                tarfile.USTAR_FORMAT,
            ),
        )
        for label, mutate, order, tar_format in cases:
            with self.subTest(label=label):
                self._linux_archive().write_bytes(original)
                self._rewrite_linux_tar(
                    mutate,
                    order=order,
                    tar_format=tar_format,
                )
                self._assert_bundle_rejected("canonical tar metadata")

        for label, offset in (("devmajor", 329), ("devminor", 337)):
            with self.subTest(label=label):
                self._linux_archive().write_bytes(original)
                self._patch_tar_binary_numeric_field(offset, 1)
                self._assert_bundle_rejected("canonical tar metadata")

    def test_rejects_noncanonical_gzip_header(self) -> None:
        archive = self._linux_archive()
        original = archive.read_bytes()
        cases = (
            ("mtime", 4, 1),
            ("compression flags", 8, 0),
            ("operating system", 9, 3),
        )
        for label, offset, value in cases:
            with self.subTest(label=label):
                encoded = bytearray(original)
                encoded[offset] = value
                archive.write_bytes(encoded)
                self._assert_bundle_rejected("canonical gzip header")

    def test_rejects_a_second_empty_gzip_member(self) -> None:
        archive = self._linux_archive()
        trailing_member = io.BytesIO()
        with gzip.GzipFile(
            fileobj=trailing_member,
            mode="wb",
            filename="",
            mtime=0,
        ):
            pass
        archive.write_bytes(archive.read_bytes() + trailing_member.getvalue())

        self._assert_bundle_rejected("exactly one gzip member")

    def test_preserves_the_bounded_tar_expansion_limit(self) -> None:
        with (
            mock.patch.object(release_manifest, "MAX_TAR_STREAM_BYTES", 1024),
            self.assertRaisesRegex(ValueError, "expands beyond the size limit"),
        ):
            self.build_manifest(
                dist=self.dist,
                version=self.version,
                source_commit=self.source_commit,
            )

    @unittest.skipIf(os.name == "nt", "Tar symlink construction is not portable on Windows")
    def test_rejects_symlink_entries(self) -> None:
        archive = next(self.dist.glob("*aarch64-unknown-linux-gnu.tar.gz"))
        prefix = "calcifer-v0.1.0-alpha.4-aarch64-unknown-linux-gnu"
        with archive.open("wb") as raw:
            with gzip.GzipFile(
                fileobj=raw,
                mode="wb",
                filename="",
                mtime=0,
            ) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as malformed:
                    directory = tarfile.TarInfo(prefix)
                    directory.type = tarfile.DIRTYPE
                    package_release._configure_tar_info(directory, 0o755)
                    malformed.addfile(directory)
                    link = tarfile.TarInfo(f"{prefix}/calcifer")
                    link.type = tarfile.SYMTYPE
                    link.linkname = "/tmp/not-calcifer"
                    malformed.addfile(link)

        with self.assertRaisesRegex(ValueError, "regular files and directories"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

    def test_rejects_invalid_version_and_source_commit(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid semantic version"):
            self.build_manifest(
                dist=self.dist,
                version="01.0.0",
                source_commit="0123456789abcdef0123456789abcdef01234567",
            )

        with self.assertRaisesRegex(ValueError, "source commit"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit="main",
            )

        with self.assertRaisesRegex(ValueError, "tag ref digest"):
            self.build_manifest(
                dist=self.dist,
                version="0.1.0-alpha.4",
                source_commit=self.source_commit,
                tag_ref_digest="main",
            )


if __name__ == "__main__":
    unittest.main()
