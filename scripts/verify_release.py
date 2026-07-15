#!/usr/bin/env python3
"""Fail closed unless a GitHub release readback exactly matches local assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

try:
    from scripts import release_manifest
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    import release_manifest


MAX_RELEASE_JSON_BYTES = 1024 * 1024
MAX_RELEASE_ATTESTATION_JSON_BYTES = 4 * 1024 * 1024
MAX_CHECKSUM_BYTES = 64 * 1024
CHECKSUM_PATTERN = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9.+_-]*)\n$")
STAGES = ("draft", "published")
RELEASE_PREDICATE_TYPE = "https://in-toto.io/attestation/release/v0.2"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_asset_names(version: str) -> set[str]:
    release_manifest.release_channel(version)
    return {
        release_manifest.MANIFEST_NAME,
        release_manifest.CHECKSUM_NAME,
        *(
            release_manifest.archive_name(version, target)
            for target in release_manifest.SUPPORTED_TARGETS
        ),
    }


def verify_local_bundle(
    *,
    dist: Path,
    version: str,
    source_commit: str,
) -> dict[str, tuple[int, str]]:
    """Validate every local release byte and the canonical manifest semantics."""

    if dist.is_symlink() or not dist.is_dir():
        raise ValueError("release bundle directory must be a regular directory")
    dist = dist.resolve(strict=True)
    expected_names = _expected_asset_names(version)
    actual_names = {entry.name for entry in dist.iterdir()}
    if actual_names != expected_names:
        raise ValueError("local release asset name set does not match the release contract")

    sizes: dict[str, int] = {}
    for name in sorted(expected_names):
        path = dist / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"local release asset is not a regular file: {name}")
        size = path.stat().st_size
        if (
            name == release_manifest.MANIFEST_NAME
            and size > release_manifest.MAX_MANIFEST_BYTES
        ):
            raise ValueError("release manifest exceeds the 64 KiB limit")
        if name == release_manifest.CHECKSUM_NAME and size > MAX_CHECKSUM_BYTES:
            raise ValueError("checksum file exceeds the 64 KiB limit")
        if (
            name not in (release_manifest.MANIFEST_NAME, release_manifest.CHECKSUM_NAME)
            and size > release_manifest.MAX_ARCHIVE_BYTES
        ):
            raise ValueError(f"release archive is too large: {name}")
        sizes[name] = size

    local = {
        name: (sizes[name], _sha256(dist / name)) for name in sorted(expected_names)
    }
    _validate_checksums(dist / release_manifest.CHECKSUM_NAME, local)
    release_manifest.validate_manifest(
        dist=dist,
        version=version,
        source_commit=source_commit,
    )
    return local


def _validate_checksums(
    checksum_path: Path,
    local: dict[str, tuple[int, str]],
) -> None:
    if checksum_path.stat().st_size > MAX_CHECKSUM_BYTES:
        raise ValueError("checksum file exceeds the 64 KiB limit")
    try:
        encoded = checksum_path.read_bytes()
        text = encoded.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("checksum file must be canonical ASCII") from error
    if not text or not text.endswith("\n"):
        raise ValueError("checksum file must be canonical and end with a newline")

    checksums: dict[str, str] = {}
    ordered_names: list[str] = []
    for line in text.splitlines(keepends=True):
        match = CHECKSUM_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError("checksum file is not in canonical SHA256SUMS format")
        digest, name = match.groups()
        if name in checksums:
            raise ValueError("checksum file contains a duplicate asset")
        checksums[name] = digest
        ordered_names.append(name)

    expected_names = set(local) - {release_manifest.CHECKSUM_NAME}
    if set(checksums) != expected_names:
        raise ValueError("checksum name set does not cover every non-checksum asset")
    if ordered_names != sorted(ordered_names):
        raise ValueError("checksum file entries must use canonical name order")
    for name, expected_digest in checksums.items():
        if local[name][1] != expected_digest:
            raise ValueError(f"checksum digest does not match local asset: {name}")


def load_release(path: Path) -> dict[str, object]:
    """Load one bounded GitHub Releases API response from a regular file."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("release readback must be a regular file")
    if path.stat().st_size > MAX_RELEASE_JSON_BYTES:
        raise ValueError("release readback exceeds the 1 MiB limit")
    try:
        document = json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("release readback must be valid JSON") from error
    if not isinstance(document, dict):
        raise ValueError("release readback must be a JSON object")
    return document


def load_release_attestation(path: Path) -> dict[str, object]:
    """Load one bounded `gh release verify --format json` result."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("release attestation readback must be a regular file")
    if path.stat().st_size > MAX_RELEASE_ATTESTATION_JSON_BYTES:
        raise ValueError("release attestation readback exceeds the 4 MiB limit")
    try:
        document = json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("release attestation readback must be valid JSON") from error
    if not isinstance(document, dict):
        raise ValueError("release attestation readback must be a JSON object")
    return document


def _required_boolean(release: dict[str, object], field: str) -> bool:
    value = release.get(field)
    if type(value) is not bool:
        raise ValueError(f"release {field} state must be a boolean")
    return value


def verify_release(
    *,
    release: dict[str, object],
    dist: Path,
    version: str,
    source_commit: str,
    expected_prerelease: bool,
    stage: str,
) -> None:
    """Validate lifecycle state and every uploaded asset against local bytes."""

    if stage not in STAGES:
        raise ValueError("release verification stage must be draft or published")
    local = verify_local_bundle(
        dist=dist,
        version=version,
        source_commit=source_commit,
    )
    expected_tag = f"v{version}"
    if release.get("tag_name") != expected_tag:
        raise ValueError("release tag does not match the package version")
    if _required_boolean(release, "prerelease") is not expected_prerelease:
        raise ValueError("release prerelease state does not match the version channel")

    expected_draft = stage == "draft"
    expected_immutable = stage == "published"
    if _required_boolean(release, "draft") is not expected_draft:
        raise ValueError(f"release draft state does not match the {stage} stage")
    if _required_boolean(release, "immutable") is not expected_immutable:
        raise ValueError(f"release immutable state does not match the {stage} stage")

    published_at = release.get("published_at")
    if expected_draft and published_at is not None:
        raise ValueError("draft release must not have a publication timestamp")
    if not expected_draft and (not isinstance(published_at, str) or not published_at):
        raise ValueError("published release must have a publication timestamp")

    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError("release assets must be a JSON array")
    remote: dict[str, tuple[int, str]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("release asset must be a JSON object")
        name = asset.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("release asset name must be a non-empty string")
        if name in remote:
            raise ValueError(f"duplicate release asset: {name}")
        if asset.get("state") != "uploaded":
            raise ValueError(f"release asset is not uploaded: {name}")
        size = asset.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError(f"release asset size is invalid: {name}")
        digest = asset.get("digest")
        if not isinstance(digest, str):
            raise ValueError(f"release asset digest is missing: {name}")
        remote[name] = (size, digest)

    if set(remote) != set(local):
        raise ValueError("remote release asset name set does not match local assets")
    for name, (local_size, local_digest) in local.items():
        remote_size, remote_digest = remote[name]
        if remote_size != local_size:
            raise ValueError(f"release asset size does not match local bytes: {name}")
        if remote_digest != f"sha256:{local_digest}":
            raise ValueError(f"release asset digest does not match local bytes: {name}")


def verify_release_attestation(
    *,
    attestation: dict[str, object],
    dist: Path,
    version: str,
    source_commit: str,
    tag_ref_digest: str,
) -> None:
    """Bind a verified GitHub release attestation to this exact local bundle."""

    if release_manifest.SOURCE_COMMIT_PATTERN.fullmatch(tag_ref_digest) is None:
        raise ValueError("tag ref digest must be a lowercase 40-character Git SHA")
    local = verify_local_bundle(
        dist=dist,
        version=version,
        source_commit=source_commit,
    )
    verification = attestation.get("verificationResult")
    if not isinstance(verification, dict):
        raise ValueError("release attestation verification result is missing")
    statement = verification.get("statement")
    if not isinstance(statement, dict):
        raise ValueError("release attestation statement is missing")
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise ValueError("release attestation statement type is unsupported")
    if statement.get("predicateType") != RELEASE_PREDICATE_TYPE:
        raise ValueError("release attestation predicate type is unsupported")

    expected_tag = f"v{version}"
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ValueError("release attestation predicate is missing")
    if predicate.get("repository") != release_manifest.REPOSITORY:
        raise ValueError("release attestation repository does not match")
    if predicate.get("tag") != expected_tag:
        raise ValueError("release attestation tag does not match")

    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        raise ValueError("release attestation subjects must be a JSON array")
    package_subjects: list[dict[str, object]] = []
    asset_subjects: dict[str, str] = {}
    for subject in subjects:
        if not isinstance(subject, dict):
            raise ValueError("release attestation subject must be a JSON object")
        digest = subject.get("digest")
        if not isinstance(digest, dict):
            raise ValueError("release attestation subject digest is missing")
        uri = subject.get("uri")
        name = subject.get("name")
        if isinstance(uri, str):
            if name is not None:
                raise ValueError("release attestation subject identity is ambiguous")
            package_subjects.append(subject)
            continue
        if not isinstance(name, str) or not name:
            raise ValueError("release attestation asset subject name is invalid")
        if name in asset_subjects:
            raise ValueError(f"duplicate release attestation asset subject: {name}")
        sha256 = digest.get("sha256")
        if not isinstance(sha256, str):
            raise ValueError(f"release attestation asset digest is missing: {name}")
        asset_subjects[name] = sha256

    if len(package_subjects) != 1:
        raise ValueError("release attestation package subject is not unique")
    package = package_subjects[0]
    if package.get("uri") != (
        f"pkg:github/{release_manifest.REPOSITORY}@{expected_tag}"
    ):
        raise ValueError("release attestation package identity does not match")
    package_digest = package.get("digest")
    if (
        not isinstance(package_digest, dict)
        or package_digest.get("sha1") != tag_ref_digest
    ):
        raise ValueError("release attestation tag ref digest does not match")

    if set(asset_subjects) != set(local):
        raise ValueError("release attestation asset subject set does not match")
    for name, (_, local_digest) in local.items():
        if asset_subjects[name] != local_digest:
            raise ValueError(
                f"release attestation asset digest does not match local bytes: {name}"
            )


def _parse_boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-json", type=Path)
    parser.add_argument("--release-attestation-json", type=Path)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--tag-ref-digest")
    parser.add_argument("--expected-prerelease", type=_parse_boolean)
    parser.add_argument("--stage", choices=STAGES)
    parser.add_argument("--local-only", action="store_true")
    arguments = parser.parse_args()

    try:
        if arguments.release_attestation_json is not None:
            if arguments.local_only or any(
                value is not None
                for value in (
                    arguments.release_json,
                    arguments.expected_prerelease,
                    arguments.stage,
                )
            ):
                parser.error(
                    "--release-attestation-json cannot be combined with other modes"
                )
            if arguments.tag_ref_digest is None:
                parser.error(
                    "--release-attestation-json requires --tag-ref-digest"
                )
            verify_release_attestation(
                attestation=load_release_attestation(
                    arguments.release_attestation_json
                ),
                dist=arguments.dist,
                version=arguments.version,
                source_commit=arguments.source_commit,
                tag_ref_digest=arguments.tag_ref_digest,
            )
            return 0
        if arguments.local_only:
            if any(
                value is not None
                for value in (
                    arguments.release_json,
                    arguments.expected_prerelease,
                    arguments.stage,
                    arguments.tag_ref_digest,
                )
            ):
                parser.error(
                    "--local-only cannot be combined with remote release arguments"
                )
            verify_local_bundle(
                dist=arguments.dist,
                version=arguments.version,
                source_commit=arguments.source_commit,
            )
            return 0
        if (
            arguments.release_json is None
            or arguments.expected_prerelease is None
            or arguments.stage is None
        ):
            parser.error(
                "remote verification requires --release-json, "
                "--expected-prerelease, and --stage"
            )
        if arguments.tag_ref_digest is not None:
            parser.error("--tag-ref-digest is only valid for release attestations")
        verify_release(
            release=load_release(arguments.release_json),
            dist=arguments.dist,
            version=arguments.version,
            source_commit=arguments.source_commit,
            expected_prerelease=arguments.expected_prerelease,
            stage=arguments.stage,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
