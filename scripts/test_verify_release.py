import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import package_release, release_manifest, verify_release


class VerifyReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.version = "0.1.0-alpha.4"
        self.tag = f"v{self.version}"
        self.source_commit = "0123456789abcdef0123456789abcdef01234567"
        # Annotated tags have a raw tag-object digest distinct from the commit
        # they peel to. GitHub release attestations bind this raw ref digest.
        self.tag_ref_digest = "89abcdef0123456789abcdef0123456789abcdef"
        self.project = self.root / "project"
        self.project.mkdir()

        for name, contents in (
            ("README.md", "read me\n"),
            ("LICENSE", "license\n"),
            ("SECURITY.md", "security\n"),
        ):
            (self.project / name).write_text(contents, encoding="utf-8")

        for target in release_manifest.SUPPORTED_TARGETS:
            binary = self.root / f"calcifer-{target}"
            binary.write_bytes(f"synthetic binary for {target}\n".encode())
            binary.chmod(0o755)
            package_release.build_archive(
                project_root=self.project,
                binary=binary,
                output_dir=self.dist,
                target=target,
                version=self.version,
            )
        release_manifest.write_manifest(
            dist=self.dist,
            output=self.dist / release_manifest.MANIFEST_NAME,
            version=self.version,
            source_commit=self.source_commit,
            tag_ref_digest=self.tag_ref_digest,
        )
        self.write_checksums()

    def write_checksums(self) -> None:
        covered = sorted(
            path for path in self.dist.iterdir() if path.name != "SHA256SUMS"
        )
        checksums = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in covered
        )
        (self.dist / "SHA256SUMS").write_text(checksums, encoding="ascii")

    def release_document(self, *, stage: str = "draft") -> dict[str, object]:
        assets = []
        for index, path in enumerate(sorted(self.dist.iterdir()), start=1):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            assets.append(
                {
                    "id": index,
                    "name": path.name,
                    "size": path.stat().st_size,
                    "digest": f"sha256:{digest}",
                    "state": "uploaded",
                }
            )
        published = stage == "published"
        return {
            "tag_name": self.tag,
            "draft": not published,
            "prerelease": True,
            "immutable": published,
            "published_at": "2026-07-15T00:00:00Z" if published else None,
            "assets": assets,
        }

    def release_attestation_document(self) -> dict[str, object]:
        subjects: list[dict[str, object]] = [
            {
                "uri": f"pkg:github/kazu-42/calcifer@{self.tag}",
                "digest": {"sha1": self.tag_ref_digest},
            }
        ]
        subjects.extend(
            {
                "name": path.name,
                "digest": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
            }
            for path in sorted(self.dist.iterdir())
        )
        return {
            "verificationResult": {
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": subjects,
                    "predicateType": "https://in-toto.io/attestation/release/v0.2",
                    "predicate": {
                        "repository": "kazu-42/calcifer",
                        "tag": self.tag,
                    },
                }
            }
        }

    def verify(self, document: dict[str, object], *, stage: str = "draft") -> None:
        verify_release.verify_release(
            release=document,
            dist=self.dist,
            version=self.version,
            source_commit=self.source_commit,
            tag_ref_digest=self.tag_ref_digest,
            expected_prerelease=True,
            stage=stage,
        )

    def test_accepts_exact_draft_and_published_release_readbacks(self) -> None:
        self.verify(self.release_document())
        self.verify(self.release_document(stage="published"), stage="published")
        verify_release.verify_local_bundle(
            dist=self.dist,
            version=self.version,
            source_commit=self.source_commit,
            tag_ref_digest=self.tag_ref_digest,
        )

    def test_rejects_semantically_invalid_manifest_with_matching_checksums(self) -> None:
        manifest_path = self.dist / release_manifest.MANIFEST_NAME
        document = json.loads(manifest_path.read_bytes())
        document["unexpected"] = True
        manifest_path.write_bytes(
            json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
            + b"\n"
        )
        self.write_checksums()

        with self.assertRaisesRegex(ValueError, "manifest does not match"):
            self.verify(self.release_document())

    def test_rejects_noncanonical_manifest_with_matching_checksums(self) -> None:
        manifest_path = self.dist / release_manifest.MANIFEST_NAME
        document = json.loads(manifest_path.read_bytes())
        manifest_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.write_checksums()

        with self.assertRaisesRegex(ValueError, "manifest does not match"):
            self.verify(self.release_document())

    def test_rejects_manifest_for_a_different_source_commit(self) -> None:
        with self.assertRaisesRegex(ValueError, "manifest does not match"):
            verify_release.verify_release(
                release=self.release_document(),
                dist=self.dist,
                version=self.version,
                source_commit="f" * 40,
                tag_ref_digest=self.tag_ref_digest,
                expected_prerelease=True,
                stage="draft",
            )

    def test_rejects_oversized_archive_before_hashing_any_asset(self) -> None:
        archive = self.dist / release_manifest.archive_name(
            self.version,
            release_manifest.SUPPORTED_TARGETS[0],
        )

        with (
            mock.patch.object(
                release_manifest,
                "MAX_ARCHIVE_BYTES",
                archive.stat().st_size - 1,
            ),
            mock.patch.object(
                verify_release,
                "_sha256",
                side_effect=AssertionError("oversized inputs must not be hashed"),
            ),
            self.assertRaisesRegex(ValueError, "release archive is too large"),
        ):
            verify_release.verify_local_bundle(
                dist=self.dist,
                version=self.version,
                source_commit=self.source_commit,
                tag_ref_digest=self.tag_ref_digest,
            )

    def test_accepts_exact_release_attestation_subjects(self) -> None:
        verify_release.verify_release_attestation(
            attestation=self.release_attestation_document(),
            dist=self.dist,
            version=self.version,
            source_commit=self.source_commit,
            tag_ref_digest=self.tag_ref_digest,
        )

    def test_rejects_release_attestation_tag_ref_or_asset_drift(self) -> None:
        wrong_tag_ref = self.release_attestation_document()
        wrong_tag_ref["verificationResult"]["statement"]["subject"][0]["digest"] = {
            "sha1": "f" * 40
        }
        with self.assertRaisesRegex(ValueError, "tag ref digest"):
            verify_release.verify_release_attestation(
                attestation=wrong_tag_ref,
                dist=self.dist,
                version=self.version,
                source_commit=self.source_commit,
                tag_ref_digest=self.tag_ref_digest,
            )

        missing_asset = self.release_attestation_document()
        missing_asset["verificationResult"]["statement"]["subject"].pop()
        with self.assertRaisesRegex(ValueError, "asset subject set"):
            verify_release.verify_release_attestation(
                attestation=missing_asset,
                dist=self.dist,
                version=self.version,
                source_commit=self.source_commit,
                tag_ref_digest=self.tag_ref_digest,
            )

    def test_rejects_missing_duplicate_or_unexpected_assets(self) -> None:
        missing = self.release_document()
        missing["assets"] = missing["assets"][:-1]
        with self.assertRaisesRegex(ValueError, "asset name set"):
            self.verify(missing)

        duplicate = self.release_document()
        duplicate["assets"] = [*duplicate["assets"], duplicate["assets"][0]]
        with self.assertRaisesRegex(ValueError, "duplicate release asset"):
            self.verify(duplicate)

        unexpected = self.release_document()
        unexpected["assets"][0]["name"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "asset name set"):
            self.verify(unexpected)

    def test_rejects_size_digest_and_upload_state_mismatches(self) -> None:
        bad_size = self.release_document()
        bad_size["assets"][0]["size"] += 1
        with self.assertRaisesRegex(ValueError, "size does not match"):
            self.verify(bad_size)

        bad_digest = self.release_document()
        bad_digest["assets"][0]["digest"] = f"sha256:{'0' * 64}"
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            self.verify(bad_digest)

        incomplete = self.release_document()
        incomplete["assets"][0]["state"] = "new"
        with self.assertRaisesRegex(ValueError, "not uploaded"):
            self.verify(incomplete)

    def test_rejects_wrong_release_lifecycle_and_channel(self) -> None:
        immutable_draft = self.release_document()
        immutable_draft["immutable"] = True
        with self.assertRaisesRegex(ValueError, "immutable state"):
            self.verify(immutable_draft)

        mutable_publish = self.release_document(stage="published")
        mutable_publish["immutable"] = False
        with self.assertRaisesRegex(ValueError, "immutable state"):
            self.verify(mutable_publish, stage="published")

        wrong_channel = self.release_document()
        wrong_channel["prerelease"] = False
        with self.assertRaisesRegex(ValueError, "prerelease state"):
            self.verify(wrong_channel)

        wrong_tag = self.release_document()
        wrong_tag["tag_name"] = "v9.9.9"
        with self.assertRaisesRegex(ValueError, "tag"):
            self.verify(wrong_tag)

    def test_rejects_noncanonical_or_incomplete_checksum_file(self) -> None:
        checksum_path = self.dist / "SHA256SUMS"
        checksum_path.write_text(
            checksum_path.read_text(encoding="ascii").splitlines(keepends=True)[0],
            encoding="ascii",
        )
        with self.assertRaisesRegex(ValueError, "checksum name set"):
            self.verify(self.release_document())

        covered = sorted(path for path in self.dist.iterdir() if path.name != "SHA256SUMS")
        checksum_path.write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()} *{path.name}\n"
                for path in covered
            ),
            encoding="ascii",
        )
        with self.assertRaisesRegex(ValueError, "canonical"):
            self.verify(self.release_document())

    def test_rejects_malformed_json_input(self) -> None:
        release_path = self.root / "release.json"
        release_path.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "JSON object"):
            verify_release.load_release(release_path)

        release_path.write_text("not json", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "valid JSON"):
            verify_release.load_release(release_path)

    def test_json_fixture_is_round_trip_compatible_with_loader(self) -> None:
        release_path = self.root / "release.json"
        release_path.write_text(json.dumps(self.release_document()), encoding="utf-8")
        self.verify(verify_release.load_release(release_path))


if __name__ == "__main__":
    unittest.main()
