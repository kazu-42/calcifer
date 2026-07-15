import hashlib
import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from scripts import package_release, publish_release, release_manifest


class FakeGitHubClient:
    def __init__(self, release: dict[str, object]) -> None:
        self.release = release
        self.pages: dict[int, list[dict[str, object]]] = {1: [release]}
        self.calls: list[tuple[object, ...]] = []
        self.patch_calls: list[tuple[int, str]] = []
        self.patch_failure = False
        self.patch_takes_effect = True
        self.publish_mutable = False
        self.artifact_failure: str | None = None
        self.read_failures = 0
        self.list_read_failures = 0
        self.mutable_reads_before_immutable: int | None = None
        self.release_attestation: dict[str, object] = {}

    def immutable_release_settings(self) -> dict[str, object]:
        self.calls.append(("immutable_settings",))
        return {"enabled": True, "enforced_by_owner": False}

    def release_tag_ruleset(self) -> dict[str, object]:
        self.calls.append(("ruleset",))
        return {
            "id": publish_release.RELEASE_TAG_RULESET_ID,
            "name": "Immutable release tags",
            "enforcement": "active",
            "target": "tag",
            "source_type": "Repository",
            "source": release_manifest.REPOSITORY,
            "conditions": {
                "ref_name": {"include": ["refs/tags/v*"], "exclude": []}
            },
            "rules": [{"type": "update"}, {"type": "deletion"}],
            "bypass_actors": [],
        }

    def tag_ref(self, tag: str) -> dict[str, object]:
        self.calls.append(("tag_ref", tag))
        return {
            "object": {
                "sha": "89abcdef0123456789abcdef0123456789abcdef",
                "type": "tag",
            }
        }

    def tagged_commit(self, tag: str) -> str:
        self.calls.append(("tagged_commit", tag))
        return "0123456789abcdef0123456789abcdef01234567"

    def list_releases_page(self, page: int) -> list[dict[str, object]]:
        self.calls.append(("list_releases_page", page))
        if self.list_read_failures:
            self.list_read_failures -= 1
            raise publish_release.CommandFailure("synthetic list failure")
        if (
            page == 1
            and self.mutable_reads_before_immutable is not None
            and self.release.get("draft") is False
            and self.release.get("immutable") is False
        ):
            if self.mutable_reads_before_immutable == 0:
                self.release = {**self.release, "immutable": True}
                self.pages = {1: [self.release]}
            else:
                self.mutable_reads_before_immutable -= 1
        return self.pages.get(page, [])

    def release_by_id(self, release_id: int) -> dict[str, object]:
        self.calls.append(("release_by_id", release_id))
        if self.read_failures:
            self.read_failures -= 1
            raise publish_release.CommandFailure("synthetic read failure")
        return self.release

    def verify_artifact_attestation(
        self, path: Path, *, tag: str, source_commit: str
    ) -> None:
        self.calls.append(("verify_artifact", path.name, tag, source_commit))
        if self.artifact_failure == path.name:
            raise publish_release.CommandFailure("synthetic attestation failure")

    def publish_release(self, release_id: int, *, make_latest: str) -> None:
        self.calls.append(("publish_release", release_id, make_latest))
        self.patch_calls.append((release_id, make_latest))
        if self.patch_takes_effect:
            self.release = {
                **self.release,
                "draft": False,
                "immutable": not self.publish_mutable,
                "published_at": "2026-07-15T00:00:00Z",
            }
            self.pages = {1: [self.release]}
        if self.patch_failure:
            raise publish_release.CommandFailure("synthetic ambiguous write failure")

    def verify_release_attestation(self, tag: str) -> dict[str, object]:
        self.calls.append(("verify_release_attestation", tag))
        return self.release_attestation

    def verify_release_asset(self, tag: str, path: Path) -> None:
        self.calls.append(("verify_release_asset", tag, path.name))


class PublishReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.version = "0.1.0-alpha.4"
        self.tag = f"v{self.version}"
        self.source_commit = "0123456789abcdef0123456789abcdef01234567"
        self.tag_ref_digest = "89abcdef0123456789abcdef0123456789abcdef"

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
        covered = sorted(
            path for path in self.dist.iterdir() if path.name != "SHA256SUMS"
        )
        (self.dist / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in covered
            ),
            encoding="ascii",
        )
        self.release = self.release_document(stage="draft")
        self.client = FakeGitHubClient(self.release)
        self.client.release_attestation = self.release_attestation_document()
        self.publisher = publish_release.Publisher(
            self.client,
            sleep=lambda _: None,
            reconcile_attempts=2,
            verification_attempts=2,
        )

    def release_document(self, *, stage: str) -> dict[str, object]:
        published = stage != "draft"
        immutable = stage == "immutable"
        return {
            "id": 42,
            "tag_name": self.tag,
            "draft": not published,
            "prerelease": True,
            "immutable": immutable,
            "published_at": "2026-07-15T00:00:00Z" if published else None,
            "assets": [
                {
                    "id": index,
                    "name": path.name,
                    "size": path.stat().st_size,
                    "digest": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
                    "state": "uploaded",
                }
                for index, path in enumerate(sorted(self.dist.iterdir()), start=1)
            ],
        }

    def release_attestation_document(self) -> dict[str, object]:
        return {
            "verificationResult": {
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": [
                        {
                            "uri": f"pkg:github/kazu-42/calcifer@{self.tag}",
                            "digest": {"sha1": self.tag_ref_digest},
                        },
                        *(
                            {
                                "name": path.name,
                                "digest": {
                                    "sha256": hashlib.sha256(
                                        path.read_bytes()
                                    ).hexdigest()
                                },
                            }
                            for path in sorted(self.dist.iterdir())
                        ),
                    ],
                    "predicateType": "https://in-toto.io/attestation/release/v0.2",
                    "predicate": {
                        "repository": release_manifest.REPOSITORY,
                        "tag": self.tag,
                    },
                }
            }
        }

    def test_lists_every_page_and_rejects_missing_or_duplicate_tag(self) -> None:
        nonmatches = [
            {**self.release, "id": index + 100, "tag_name": f"v0.0.{index}"}
            for index in range(publish_release.RELEASES_PER_PAGE)
        ]
        self.client.pages = {1: nonmatches, 2: [self.release]}
        found = publish_release.find_unique_release(self.client, self.tag)
        self.assertEqual(found["id"], 42)
        self.assertEqual(
            [call for call in self.client.calls if call[0] == "list_releases_page"],
            [("list_releases_page", 1), ("list_releases_page", 2)],
        )

        self.client.pages = {1: []}
        with self.assertRaisesRegex(ValueError, "no release"):
            publish_release.find_unique_release(self.client, self.tag)

        self.client.pages = {1: [self.release, {**self.release, "id": 43}]}
        with self.assertRaisesRegex(ValueError, "multiple releases"):
            publish_release.find_unique_release(self.client, self.tag)

    def test_refuses_incomplete_release_pagination(self) -> None:
        self.client.pages = {
            1: [
                {**self.release, "id": index + 100, "tag_name": f"v0.0.{index}"}
                for index in range(publish_release.RELEASES_PER_PAGE)
            ]
        }
        with (
            mock.patch.object(publish_release, "MAX_RELEASE_PAGES", 1),
            self.assertRaisesRegex(ValueError, "pagination limit"),
        ):
            publish_release.find_unique_release(self.client, self.tag)

    def test_default_preflight_is_read_only_and_verifies_attestations(self) -> None:
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)

        self.assertEqual(context.state, "draft")
        self.assertEqual(context.release_id, 42)
        self.assertEqual(self.client.patch_calls, [])
        verified = [
            call[1] for call in self.client.calls if call[0] == "verify_artifact"
        ]
        self.assertEqual(verified, sorted(path.name for path in self.dist.iterdir()))

    def test_publishes_exact_draft_once_then_verifies_attestations(self) -> None:
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        result = self.publisher.publish(context)

        self.assertEqual(result.state, "immutable")
        self.assertEqual(self.client.patch_calls, [(42, "false")])
        publish_index = next(
            index
            for index, call in enumerate(self.client.calls)
            if call[0] == "publish_release"
        )
        before_publish = self.client.calls[:publish_index]
        self.assertGreaterEqual(
            sum(call[0] == "immutable_settings" for call in before_publish), 2
        )
        self.assertGreaterEqual(sum(call[0] == "ruleset" for call in before_publish), 2)
        self.assertFalse(
            any(call[0] == "release_by_id" for call in before_publish),
            "drafts must only be read through the documented List releases API",
        )
        self.assertTrue(
            all(
                index < publish_index
                for index, call in enumerate(self.client.calls)
                if call[0] == "verify_artifact"
            )
        )
        verified_assets = [
            call[2] for call in self.client.calls if call[0] == "verify_release_asset"
        ]
        self.assertEqual(
            verified_assets, sorted(path.name for path in self.dist.iterdir())
        )

    def test_artifact_attestation_failure_prevents_publish(self) -> None:
        self.client.artifact_failure = sorted(
            path.name for path in self.dist.iterdir()
        )[0]
        with self.assertRaisesRegex(RuntimeError, "artifact attestation"):
            self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        self.assertEqual(self.client.patch_calls, [])

    def test_ambiguous_patch_reconciles_without_retry(self) -> None:
        self.client.patch_failure = True
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        result = self.publisher.publish(context)

        self.assertEqual(result.state, "immutable")
        self.assertEqual(self.client.patch_calls, [(42, "false")])

    def test_failed_patch_that_leaves_draft_is_never_retried(self) -> None:
        self.client.patch_failure = True
        self.client.patch_takes_effect = False
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        with self.assertRaisesRegex(RuntimeError, "remains an unpublished draft"):
            self.publisher.publish(context)
        self.assertEqual(self.client.patch_calls, [(42, "false")])

    def test_public_mutable_result_is_classified_as_critical(self) -> None:
        self.client.publish_mutable = True
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        with self.assertRaisesRegex(RuntimeError, "PUBLIC but not immutable"):
            self.publisher.publish(context)
        self.assertEqual(self.client.patch_calls, [(42, "false")])

    def test_transient_public_mutable_readback_can_become_immutable(self) -> None:
        self.client.publish_mutable = True
        self.client.mutable_reads_before_immutable = 1
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        result = self.publisher.publish(context)
        self.assertEqual(result.state, "immutable")
        self.assertEqual(self.client.patch_calls, [(42, "false")])

    def test_unavailable_post_patch_readback_never_causes_a_second_write(self) -> None:
        original_publish = self.client.publish_release

        def publish_then_lose_reads(release_id: int, *, make_latest: str) -> None:
            original_publish(release_id, make_latest=make_latest)
            self.client.list_read_failures = 100

        self.client.publish_release = publish_then_lose_reads
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        with self.assertRaisesRegex(RuntimeError, "outcome is unknown"):
            self.publisher.publish(context)
        self.assertEqual(self.client.patch_calls, [(42, "false")])

    def test_post_patch_attestation_failure_never_causes_a_second_write(self) -> None:
        self.client.verify_release_attestation = lambda _: (_ for _ in ()).throw(
            publish_release.CommandFailure("synthetic attestation outage")
        )
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        with self.assertRaisesRegex(RuntimeError, "release attestation"):
            self.publisher.publish(context)
        self.assertEqual(self.client.patch_calls, [(42, "false")])

    def test_existing_immutable_release_is_verification_only(self) -> None:
        self.client.release = self.release_document(stage="immutable")
        self.client.pages = {1: [self.client.release]}
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        result = self.publisher.publish(context)

        self.assertEqual(result.state, "immutable")
        self.assertEqual(self.client.patch_calls, [])
        self.assertTrue(
            any(call[0] == "verify_release_attestation" for call in self.client.calls)
        )

    def test_rejects_ruleset_or_pinned_tag_drift_before_publish(self) -> None:
        context = self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        original_ruleset = self.client.release_tag_ruleset
        self.client.release_tag_ruleset = lambda: {
            **original_ruleset(),
            "bypass_actors": [{"actor_id": 1}],
        }
        with self.assertRaisesRegex(ValueError, "bypass"):
            self.publisher.publish(context)
        self.assertEqual(self.client.patch_calls, [])

        self.client.release_tag_ruleset = original_ruleset
        self.client.tag_ref = lambda _: {
            "object": {"sha": "f" * 40, "type": "tag"}
        }
        with self.assertRaisesRegex(ValueError, "raw tag ref"):
            self.publisher.publish(context)
        self.assertEqual(self.client.patch_calls, [])

    def test_rejects_lightweight_release_tag_before_publish(self) -> None:
        self.client.tag_ref = lambda _: {
            "object": {"sha": self.tag_ref_digest, "type": "commit"}
        }

        with self.assertRaisesRegex(ValueError, "raw tag ref"):
            self.publisher.preflight(dist=self.dist, expected_tag=self.tag)
        self.assertEqual(self.client.patch_calls, [])

    def test_rejects_token_and_host_environment_overrides(self) -> None:
        for variable, value in (
            ("GH_TOKEN", "token"),
            ("GITHUB_TOKEN", "token"),
            ("GH_HOST", "attacker.invalid"),
        ):
            with self.subTest(variable=variable), self.assertRaisesRegex(
                ValueError, variable
            ):
                publish_release.validate_local_environment({variable: value})
        publish_release.validate_local_environment({"GH_HOST": "github.com"})

    def test_ci_summary_does_not_claim_admin_controls_were_checked(self) -> None:
        context = self.publisher.verify_ci_draft(
            dist=self.dist, expected_tag=self.tag
        )
        output = io.StringIO()
        with redirect_stdout(output):
            publish_release._print_summary(context, ci=True)
        rendered = output.getvalue()
        self.assertIn("immutable_release_setting: not checked", rendered)
        self.assertIn("release_tag_ruleset: not checked", rendered)
        self.assertNotIn("immutable_release_setting: enabled", rendered)


class GitHubClientTests(unittest.TestCase):
    def test_forces_public_github_host_for_every_command_family(self) -> None:
        responses = [
            subprocess.CompletedProcess([], 0, b'{"enabled":true}', b""),
            subprocess.CompletedProcess([], 0, b'{"object":{"sha":"abc"}}', b""),
            subprocess.CompletedProcess([], 0, b"[]", b""),
            subprocess.CompletedProcess([], 0, b"{}", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"{}", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
        ]
        runner = mock.Mock(side_effect=responses)
        client = publish_release.GitHubClient(runner=runner)
        client.immutable_release_settings()
        client.tag_ref("v1.2.3")
        client.list_releases_page(1)
        client.publish_release(42, make_latest="false")
        client.verify_artifact_attestation(
            Path("asset"), tag="v1.2.3", source_commit="a" * 40
        )
        client.verify_release_attestation("v1.2.3")
        client.verify_release_asset("v1.2.3", Path("asset"))

        commands = [call.args[0] for call in runner.call_args_list]
        for command in commands[:5]:
            self.assertIn("--hostname", command)
            self.assertEqual(
                command[command.index("--hostname") + 1], "github.com"
            )
        self.assertEqual(commands[3][commands[3].index("--method") + 1], "PATCH")
        self.assertTrue(any(value.endswith("/releases/42") for value in commands[3]))
        for command in commands[5:]:
            repo_index = command.index("--repo")
            self.assertEqual(
                command[repo_index + 1], "github.com/kazu-42/calcifer"
            )


if __name__ == "__main__":
    unittest.main()
