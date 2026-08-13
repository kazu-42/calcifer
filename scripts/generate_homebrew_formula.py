#!/usr/bin/env python3
"""Generate the preview Homebrew formula from one canonical release manifest."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

try:
    from scripts import release_manifest
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    import release_manifest


FORMULA_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
)
TOP_LEVEL_KEYS = {
    "attestations",
    "product",
    "release_channel",
    "repository",
    "schema",
    "source_commit",
    "tag",
    "tag_ref_digest",
    "targets",
    "version",
}
TARGET_KEYS = {
    "archive",
    "architecture",
    "binary",
    "libc",
    "os",
    "runtime_requirements",
    "target",
}
ARCHIVE_KEYS = {"format", "name", "sha256", "size"}
BINARY_KEYS = {"path", "sha256"}
EXPECTED_ATTESTATIONS = {
    "artifact": {
        "job": "publish",
        "kind": "github_artifact_attestation",
        "subjects": "release_assets",
        "workflow": release_manifest.RELEASE_WORKFLOW,
    },
    "immutable_release": {
        "kind": "github_release_attestation",
        "required": True,
    },
    "signer_workflow": {
        "repository": release_manifest.REPOSITORY,
        "workflow": release_manifest.RELEASE_WORKFLOW,
    },
}


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _lowercase_sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"release {field} digest must be lowercase SHA-256")
    return value


def _require_exact_keys(value: object, expected: set[str], field: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"release {field} shape does not match manifest v1")
    return value


def _validate_target(
    entry: object,
    *,
    version: str,
    expected_target: str,
) -> dict[str, object]:
    target = _require_exact_keys(entry, TARGET_KEYS, "target")
    metadata = release_manifest.TARGET_METADATA[expected_target]
    if target.get("target") != expected_target:
        raise ValueError("release targets must use canonical target order")
    for field in ("architecture", "os", "libc", "runtime_requirements"):
        if target.get(field) != metadata[field]:
            raise ValueError(f"release target {field} does not match manifest v1")

    archive = _require_exact_keys(target.get("archive"), ARCHIVE_KEYS, "archive")
    if archive.get("name") != release_manifest.archive_name(version, expected_target):
        raise ValueError("release archive name does not match version and target")
    if archive.get("format") != metadata["format"]:
        raise ValueError("release archive format does not match target")
    size = archive.get("size")
    if type(size) is not int or size <= 0 or size > release_manifest.MAX_ARCHIVE_BYTES:
        raise ValueError("release archive size is outside the manifest bound")
    _lowercase_sha256(archive.get("sha256"), "archive")

    binary = _require_exact_keys(target.get("binary"), BINARY_KEYS, "binary")
    expected_path = f'calcifer-v{version}-{expected_target}/{metadata["binary"]}'
    if binary.get("path") != expected_path:
        raise ValueError("release binary path does not match version and target")
    _lowercase_sha256(binary.get("sha256"), "binary")
    return target


def load_manifest(path: Path) -> dict[str, object]:
    """Read and strictly validate the canonical preview-manifest projection."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("release manifest must be a regular file")
    if path.stat().st_size > release_manifest.MAX_MANIFEST_BYTES:
        raise ValueError("release manifest exceeds the 64 KiB limit")
    encoded = path.read_bytes()
    try:
        document = json.loads(encoded)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("release manifest must be valid UTF-8 JSON") from error
    if encoded != _canonical_json(document):
        raise ValueError("release manifest must use canonical JSON encoding")

    document = _require_exact_keys(document, TOP_LEVEL_KEYS, "top-level")
    if (
        document.get("schema") != release_manifest.MANIFEST_SCHEMA
        or document.get("product") != "calcifer"
        or document.get("repository") != release_manifest.REPOSITORY
        or document.get("attestations") != EXPECTED_ATTESTATIONS
    ):
        raise ValueError("release manifest identity or attestation contract changed")
    version = document.get("version")
    if not isinstance(version, str):
        raise ValueError("release manifest version must be a string")
    if release_manifest.release_channel(version) != "preview":
        raise ValueError("Homebrew preview formula requires a preview release")
    if document.get("release_channel") != "preview" or document.get("tag") != f"v{version}":
        raise ValueError("release manifest tag or channel does not match its version")
    for field in ("source_commit", "tag_ref_digest"):
        value = document.get(field)
        if not isinstance(value, str) or release_manifest.SOURCE_COMMIT_PATTERN.fullmatch(value) is None:
            raise ValueError(f"release manifest {field} must be a lowercase Git SHA")

    targets = document.get("targets")
    if not isinstance(targets, list) or len(targets) != len(release_manifest.SUPPORTED_TARGETS):
        raise ValueError("release manifest must contain the complete target set")
    for entry, expected_target in zip(
        targets,
        release_manifest.SUPPORTED_TARGETS,
        strict=True,
    ):
        _validate_target(entry, version=version, expected_target=expected_target)
    return document


def _formula_target(document: dict[str, object], target: str) -> tuple[str, str]:
    targets = document["targets"]
    if not isinstance(targets, list):
        raise ValueError("validated target inventory was lost")
    entry = next(
        (candidate for candidate in targets if isinstance(candidate, dict) and candidate.get("target") == target),
        None,
    )
    if entry is None:
        raise ValueError("validated formula target was lost")
    archive = entry.get("archive")
    if not isinstance(archive, dict):
        raise ValueError("validated archive projection was lost")
    name = archive.get("name")
    digest = archive.get("sha256")
    if not isinstance(name, str) or not isinstance(digest, str):
        raise ValueError("validated archive projection was lost")
    return name, digest


def render_formula(document: dict[str, object]) -> str:
    """Render one deterministic binary-only preview formula."""

    version = document["version"]
    if not isinstance(version, str):
        raise ValueError("validated manifest version was lost")
    artifacts = {target: _formula_target(document, target) for target in FORMULA_TARGETS}

    def url(target: str) -> str:
        name, _ = artifacts[target]
        return f"https://github.com/kazu-42/calcifer/releases/download/v{version}/{name}"

    def digest(target: str) -> str:
        return artifacts[target][1]

    return f'''class CalciferPreview < Formula
  desc "Isolated profiles for official coding-agent CLIs (preview channel)"
  homepage "https://github.com/kazu-42/calcifer"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "{url("aarch64-apple-darwin")}"
      sha256 "{digest("aarch64-apple-darwin")}"
    else
      url "{url("x86_64-apple-darwin")}"
      sha256 "{digest("x86_64-apple-darwin")}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "{url("aarch64-unknown-linux-gnu")}"
      sha256 "{digest("aarch64-unknown-linux-gnu")}"
    else
      url "{url("x86_64-unknown-linux-gnu")}"
      sha256 "{digest("x86_64-unknown-linux-gnu")}"
    end
  end

  def install
    bin.install "calcifer"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/calcifer --version")
  end
end
'''


def write_formula(*, output: Path, rendered: str) -> None:
    """Atomically replace a regular formula without following a final symlink."""

    if output.is_symlink():
        raise ValueError("formula output must not be a symbolic link")
    if output.exists() and not output.is_file():
        raise ValueError("formula output must be a regular file")
    parent = output.parent.resolve(strict=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        document = load_manifest(arguments.manifest)
        write_formula(output=arguments.output, rendered=render_formula(document))
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
