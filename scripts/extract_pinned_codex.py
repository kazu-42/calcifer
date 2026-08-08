#!/usr/bin/env python3

import argparse
import os
import pathlib
import stat
import sys
import tarfile


COPY_CHUNK_BYTES = 64 * 1024


class PinnedArchiveError(ValueError):
    """One fixed, payload-free pinned archive failure."""


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a positive integer") from error
    if parsed <= 0 or str(parsed) != value:
        raise argparse.ArgumentTypeError("expected a canonical positive integer")
    return parsed


def _open_validated_archive(archive: pathlib.Path, max_archive_bytes: int):
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(archive, flags)
    except OSError as error:
        raise PinnedArchiveError("archive-unavailable") from error
    try:
        try:
            metadata = os.fstat(descriptor)
            visible = archive.lstat()
        except OSError as error:
            raise PinnedArchiveError("archive-unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino, metadata.st_size)
            != (visible.st_dev, visible.st_ino, visible.st_size)
        ):
            raise PinnedArchiveError("archive-shape")
        if metadata.st_size <= 0:
            raise PinnedArchiveError("archive-shape")
        if metadata.st_size > max_archive_bytes:
            raise PinnedArchiveError("archive-too-large")
        try:
            return os.fdopen(descriptor, mode="rb")
        except OSError as error:
            raise PinnedArchiveError("archive-unavailable") from error
    except BaseException:
        os.close(descriptor)
        raise


def _remove_created_output(
    output: pathlib.Path, created_identity: tuple[int, int] | None
) -> bool:
    if created_identity is None:
        return True
    try:
        metadata = output.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if (
        stat.S_ISREG(metadata.st_mode)
        and (metadata.st_dev, metadata.st_ino) == created_identity
    ):
        try:
            output.unlink()
        except OSError:
            return False
        return True
    return False


def extract_pinned_codex(
    *,
    archive: pathlib.Path,
    expected_entry: str,
    output: pathlib.Path,
    max_archive_bytes: int,
    max_extracted_bytes: int,
) -> None:
    """Extract one exact regular entry without exceeding either byte ceiling."""

    if (
        not archive.is_absolute()
        or not output.is_absolute()
        or not expected_entry
        or "/" in expected_entry
        or expected_entry in {".", ".."}
        or max_archive_bytes <= 0
        or max_extracted_bytes <= 0
    ):
        raise PinnedArchiveError("invalid-arguments")
    if os.path.lexists(output):
        raise PinnedArchiveError("output-exists")

    created_identity: tuple[int, int] | None = None
    completed = False
    try:
        with _open_validated_archive(archive, max_archive_bytes) as archive_file:
            try:
                archive_stream = tarfile.open(fileobj=archive_file, mode="r|gz")
            except (OSError, tarfile.TarError) as error:
                raise PinnedArchiveError("archive-format") from error
            with archive_stream:
                try:
                    member = archive_stream.next()
                except (OSError, tarfile.TarError) as error:
                    raise PinnedArchiveError("archive-format") from error
                if (
                    member is None
                    or member.name != expected_entry
                    or not member.isreg()
                    or member.size <= 0
                ):
                    raise PinnedArchiveError("archive-shape")
                if member.size > max_extracted_bytes:
                    raise PinnedArchiveError("entry-too-large")

                try:
                    source = archive_stream.extractfile(member)
                except (OSError, tarfile.TarError) as error:
                    raise PinnedArchiveError("archive-format") from error
                if source is None:
                    raise PinnedArchiveError("archive-shape")

                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(output, flags, 0o600)
                except FileExistsError as error:
                    raise PinnedArchiveError("output-exists") from error
                except OSError as error:
                    raise PinnedArchiveError("output-storage") from error

                metadata = os.fstat(descriptor)
                created_identity = (metadata.st_dev, metadata.st_ino)
                total = 0
                try:
                    with os.fdopen(descriptor, mode="wb") as destination:
                        while True:
                            remaining_with_sentinel = max_extracted_bytes + 1 - total
                            if remaining_with_sentinel <= 0:
                                raise PinnedArchiveError("entry-too-large")
                            try:
                                chunk = source.read(
                                    min(COPY_CHUNK_BYTES, remaining_with_sentinel)
                                )
                            except (OSError, tarfile.TarError) as error:
                                raise PinnedArchiveError("archive-format") from error
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > max_extracted_bytes:
                                raise PinnedArchiveError("entry-too-large")
                            destination.write(chunk)
                        if total != member.size:
                            raise PinnedArchiveError("archive-shape")
                        destination.flush()
                        os.fchmod(destination.fileno(), 0o700)
                        os.fsync(destination.fileno())
                except OSError as error:
                    raise PinnedArchiveError("output-storage") from error

                try:
                    extra_member = archive_stream.next()
                except (OSError, tarfile.TarError) as error:
                    raise PinnedArchiveError("archive-format") from error
                if extra_member is not None:
                    raise PinnedArchiveError("archive-shape")
        completed = True
    finally:
        if not completed and not _remove_created_output(output, created_identity):
            raise PinnedArchiveError("partial-output-retained")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bound and extract one checksum-pinned Codex archive entry."
    )
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--expected-entry", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--max-archive-bytes", required=True, type=_positive_integer
    )
    parser.add_argument(
        "--max-extracted-bytes", required=True, type=_positive_integer
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        extract_pinned_codex(
            archive=arguments.archive,
            expected_entry=arguments.expected_entry,
            output=arguments.output,
            max_archive_bytes=arguments.max_archive_bytes,
            max_extracted_bytes=arguments.max_extracted_bytes,
        )
    except PinnedArchiveError as error:
        print(f"pinned Codex archive extraction failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
