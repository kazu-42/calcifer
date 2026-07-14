import hashlib
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts import package_release


class PackageReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.project = self.root / "project"
        self.project.mkdir()

        for name, contents in (
            ("README.md", "read me\n"),
            ("LICENSE", "license\n"),
            ("SECURITY.md", "security\n"),
        ):
            (self.project / name).write_text(contents, encoding="utf-8")

        self.binary = self.root / "built-calcifer"
        self.binary.write_bytes(b"synthetic-calcifer-binary\n")
        self.binary.chmod(0o755)

    def test_builds_deterministic_tarball_with_expected_layout_and_modes(self) -> None:
        first = package_release.build_archive(
            project_root=self.project,
            binary=self.binary,
            output_dir=self.root / "first",
            target="x86_64-unknown-linux-gnu",
            version="0.1.0-alpha.3",
        )
        second = package_release.build_archive(
            project_root=self.project,
            binary=self.binary,
            output_dir=self.root / "second",
            target="x86_64-unknown-linux-gnu",
            version="0.1.0-alpha.3",
        )

        self.assertEqual(
            first.name,
            "calcifer-v0.1.0-alpha.3-x86_64-unknown-linux-gnu.tar.gz",
        )
        self.assertEqual(
            hashlib.sha256(first.read_bytes()).digest(),
            hashlib.sha256(second.read_bytes()).digest(),
        )

        prefix = "calcifer-v0.1.0-alpha.3-x86_64-unknown-linux-gnu"
        with tarfile.open(first, "r:gz") as archive:
            names = archive.getnames()
            self.assertEqual(
                names,
                [
                    prefix,
                    f"{prefix}/calcifer",
                    f"{prefix}/LICENSE",
                    f"{prefix}/README.md",
                    f"{prefix}/SECURITY.md",
                ],
            )
            binary_member = archive.getmember(f"{prefix}/calcifer")
            self.assertEqual(binary_member.mode, 0o755)
            extracted = archive.extractfile(binary_member)
            self.assertIsNotNone(extracted)
            self.assertEqual(extracted.read(), self.binary.read_bytes())
            self.assertEqual(
                archive.getmember(f"{prefix}/README.md").mode,
                0o644,
            )

    def test_builds_deterministic_windows_zip_with_executable_name(self) -> None:
        first = package_release.build_archive(
            project_root=self.project,
            binary=self.binary,
            output_dir=self.root / "first",
            target="x86_64-pc-windows-msvc",
            version="0.1.0-alpha.3",
        )
        second = package_release.build_archive(
            project_root=self.project,
            binary=self.binary,
            output_dir=self.root / "second",
            target="x86_64-pc-windows-msvc",
            version="0.1.0-alpha.3",
        )

        self.assertEqual(
            first.name,
            "calcifer-v0.1.0-alpha.3-x86_64-pc-windows-msvc.zip",
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())

        prefix = "calcifer-v0.1.0-alpha.3-x86_64-pc-windows-msvc"
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(
                archive.namelist(),
                [
                    f"{prefix}/",
                    f"{prefix}/calcifer.exe",
                    f"{prefix}/LICENSE",
                    f"{prefix}/README.md",
                    f"{prefix}/SECURITY.md",
                ],
            )
            self.assertEqual(
                archive.read(f"{prefix}/calcifer.exe"),
                self.binary.read_bytes(),
            )
            executable_mode = (
                archive.getinfo(f"{prefix}/calcifer.exe").external_attr >> 16
            ) & 0o777
            self.assertEqual(executable_mode, 0o755)

    def test_rejects_unapproved_targets_and_unsafe_version_strings(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported release target"):
            package_release.build_archive(
                project_root=self.project,
                binary=self.binary,
                output_dir=self.root / "output",
                target="wasm32-unknown-unknown",
                version="0.1.0-alpha.3",
            )

        with self.assertRaisesRegex(ValueError, "invalid release version"):
            package_release.build_archive(
                project_root=self.project,
                binary=self.binary,
                output_dir=self.root / "output",
                target="x86_64-unknown-linux-gnu",
                version="../../alpha.3",
            )

    @unittest.skipIf(os.name == "nt", "Unix mode assertions require a Unix host")
    def test_rejects_non_executable_unix_binary(self) -> None:
        self.binary.chmod(0o644)

        with self.assertRaisesRegex(ValueError, "binary is not executable"):
            package_release.build_archive(
                project_root=self.project,
                binary=self.binary,
                output_dir=self.root / "output",
                target="aarch64-apple-darwin",
                version="0.1.0-alpha.3",
            )

    @unittest.skipIf(os.name == "nt", "Symlink creation is not portable on Windows")
    def test_rejects_symlinked_binary_input(self) -> None:
        symlink = self.root / "calcifer-symlink"
        symlink.symlink_to(self.binary)

        with self.assertRaisesRegex(ValueError, "binary must be a regular file"):
            package_release.build_archive(
                project_root=self.project,
                binary=symlink,
                output_dir=self.root / "output",
                target="aarch64-apple-darwin",
                version="0.1.0-alpha.3",
            )


if __name__ == "__main__":
    unittest.main()
