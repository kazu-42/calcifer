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
from pathlib import Path

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
        with tarfile.open(archive, "w:gz") as malformed:
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
        with tarfile.open(archive, "w:gz") as malformed:
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

    @unittest.skipIf(os.name == "nt", "Tar symlink construction is not portable on Windows")
    def test_rejects_symlink_entries(self) -> None:
        archive = next(self.dist.glob("*aarch64-unknown-linux-gnu.tar.gz"))
        prefix = "calcifer-v0.1.0-alpha.4-aarch64-unknown-linux-gnu"
        with tarfile.open(archive, "w:gz") as malformed:
            directory = tarfile.TarInfo(prefix)
            directory.type = tarfile.DIRTYPE
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
