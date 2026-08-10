import io
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

import extract_pinned_codex


class PinnedCodexArchiveTests(unittest.TestCase):
    @staticmethod
    def _write_archive(
        path: pathlib.Path, entries: list[tuple[tarfile.TarInfo, bytes]]
    ) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            for member, contents in entries:
                archive.addfile(member, io.BytesIO(contents))

    @staticmethod
    def _regular_member(name: str, contents: bytes) -> tarfile.TarInfo:
        member = tarfile.TarInfo(name)
        member.mode = 0o700
        member.size = len(contents)
        return member

    def _extract(
        self,
        archive: pathlib.Path,
        output: pathlib.Path,
        *,
        max_archive_bytes: int,
        max_extracted_bytes: int,
    ) -> None:
        extract_pinned_codex.extract_pinned_codex(
            archive=archive,
            expected_entry="codex-test-target",
            output=output,
            max_archive_bytes=max_archive_bytes,
            max_extracted_bytes=max_extracted_bytes,
        )

    def test_compressed_limit_accepts_exact_size_and_rejects_one_byte_over(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "codex.tar.gz"
            output = root / "codex"
            contents = b"verified-codex"
            self._write_archive(
                archive,
                [(self._regular_member("codex-test-target", contents), contents)],
            )
            compressed_size = archive.stat().st_size

            self._extract(
                archive,
                output,
                max_archive_bytes=compressed_size,
                max_extracted_bytes=len(contents),
            )
            self.assertEqual(output.read_bytes(), contents)
            output.unlink()

            with self.assertRaisesRegex(
                extract_pinned_codex.PinnedArchiveError, "archive-too-large"
            ):
                self._extract(
                    archive,
                    output,
                    max_archive_bytes=compressed_size - 1,
                    max_extracted_bytes=len(contents),
                )
            self.assertFalse(output.exists())

    def test_extracted_limit_accepts_exact_size_and_removes_one_byte_over(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "codex.tar.gz"
            output = root / "codex"
            contents = b"x" * 65_537
            self._write_archive(
                archive,
                [(self._regular_member("codex-test-target", contents), contents)],
            )

            self._extract(
                archive,
                output,
                max_archive_bytes=archive.stat().st_size,
                max_extracted_bytes=len(contents),
            )
            self.assertEqual(output.stat().st_size, len(contents))
            output.unlink()

            with self.assertRaisesRegex(
                extract_pinned_codex.PinnedArchiveError, "entry-too-large"
            ):
                self._extract(
                    archive,
                    output,
                    max_archive_bytes=archive.stat().st_size,
                    max_extracted_bytes=len(contents) - 1,
                )
            self.assertFalse(output.exists())

    def test_high_ratio_and_extra_entry_fail_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "codex.tar.gz"
            output = root / "codex"
            high_ratio = b"\0" * (1024 * 1024)
            self._write_archive(
                archive,
                [
                    (
                        self._regular_member("codex-test-target", high_ratio),
                        high_ratio,
                    )
                ],
            )

            with self.assertRaisesRegex(
                extract_pinned_codex.PinnedArchiveError, "entry-too-large"
            ):
                self._extract(
                    archive,
                    output,
                    max_archive_bytes=archive.stat().st_size,
                    max_extracted_bytes=64 * 1024,
                )
            self.assertFalse(output.exists())

            first = b"verified"
            second = b"unexpected"
            self._write_archive(
                archive,
                [
                    (self._regular_member("codex-test-target", first), first),
                    (self._regular_member("second-entry", second), second),
                ],
            )
            with self.assertRaisesRegex(
                extract_pinned_codex.PinnedArchiveError, "archive-shape"
            ):
                self._extract(
                    archive,
                    output,
                    max_archive_bytes=archive.stat().st_size,
                    max_extracted_bytes=len(first),
                )
            self.assertFalse(output.exists())

    def test_non_regular_entry_and_preexisting_output_are_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "codex.tar.gz"
            output = root / "codex"
            link = tarfile.TarInfo("codex-test-target")
            link.type = tarfile.SYMTYPE
            link.linkname = "replacement"
            self._write_archive(archive, [(link, b"")])

            with self.assertRaisesRegex(
                extract_pinned_codex.PinnedArchiveError, "archive-shape"
            ):
                self._extract(
                    archive,
                    output,
                    max_archive_bytes=archive.stat().st_size,
                    max_extracted_bytes=1024,
                )
            self.assertFalse(output.exists())

            contents = b"verified"
            self._write_archive(
                archive,
                [(self._regular_member("codex-test-target", contents), contents)],
            )
            output.write_bytes(b"preserve-me")
            with self.assertRaisesRegex(
                extract_pinned_codex.PinnedArchiveError, "output-exists"
            ):
                self._extract(
                    archive,
                    output,
                    max_archive_bytes=archive.stat().st_size,
                    max_extracted_bytes=len(contents),
                )
            self.assertEqual(output.read_bytes(), b"preserve-me")

    def test_linked_or_malformed_archive_never_creates_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "codex.tar.gz"
            output = root / "codex"
            contents = b"verified"
            self._write_archive(
                archive,
                [(self._regular_member("codex-test-target", contents), contents)],
            )
            hard_link = root / "archive-hard-link.tar.gz"
            hard_link.hardlink_to(archive)

            with self.assertRaisesRegex(
                extract_pinned_codex.PinnedArchiveError, "archive-shape"
            ):
                self._extract(
                    archive,
                    output,
                    max_archive_bytes=archive.stat().st_size,
                    max_extracted_bytes=len(contents),
                )
            self.assertFalse(output.exists())

            hard_link.unlink()
            archive.write_bytes(b"not-a-gzip-stream")
            with self.assertRaisesRegex(
                extract_pinned_codex.PinnedArchiveError, "archive-format"
            ):
                self._extract(
                    archive,
                    output,
                    max_archive_bytes=archive.stat().st_size,
                    max_extracted_bytes=len(contents),
                )
            self.assertFalse(output.exists())

    def test_partial_cleanup_failure_is_fixed_and_does_not_unlink_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "codex.tar.gz"
            output = root / "codex"
            first = b"verified"
            second = b"unexpected"
            self._write_archive(
                archive,
                [
                    (self._regular_member("codex-test-target", first), first),
                    (self._regular_member("second-entry", second), second),
                ],
            )

            with mock.patch.object(
                pathlib.Path, "unlink", autospec=True, side_effect=PermissionError
            ):
                with self.assertRaisesRegex(
                    extract_pinned_codex.PinnedArchiveError,
                    "partial-output-retained",
                ):
                    self._extract(
                        archive,
                        output,
                        max_archive_bytes=archive.stat().st_size,
                        max_extracted_bytes=len(first),
                    )
            self.assertEqual(output.read_bytes(), first)
            output.unlink()


if __name__ == "__main__":
    unittest.main()
