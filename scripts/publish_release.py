#!/usr/bin/env python3
"""Preflight and deliberately publish one exact Calcifer release draft."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

try:
    from scripts import release_manifest, verify_release
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    import release_manifest
    import verify_release


PUBLIC_GITHUB_HOST = "github.com"
HOSTED_REPOSITORY = f"{PUBLIC_GITHUB_HOST}/{release_manifest.REPOSITORY}"
RELEASE_TAG_RULESET_ID = 18_956_764
RELEASES_PER_PAGE = 100
MAX_RELEASE_PAGES = 100
MAX_API_JSON_BYTES = 8 * 1024 * 1024
MAX_ATTESTATION_JSON_BYTES = verify_release.MAX_RELEASE_ATTESTATION_JSON_BYTES
COMMAND_TIMEOUT_SECONDS = 60
DEFAULT_RECONCILE_ATTEMPTS = 40
DEFAULT_VERIFICATION_ATTEMPTS = 10


class CommandFailure(RuntimeError):
    """A read or write through GitHub CLI failed without a trusted result."""


class GitHubClientProtocol(Protocol):
    def immutable_release_settings(self) -> dict[str, object]: ...

    def release_tag_ruleset(self) -> dict[str, object]: ...

    def tag_ref(self, tag: str) -> dict[str, object]: ...

    def tagged_commit(self, tag: str) -> str: ...

    def list_releases_page(self, page: int) -> list[dict[str, object]]: ...

    def release_by_id(self, release_id: int) -> dict[str, object]: ...

    def verify_artifact_attestation(
        self, path: Path, *, tag: str, source_commit: str
    ) -> None: ...

    def publish_release(self, release_id: int, *, make_latest: str) -> None: ...

    def verify_release_attestation(self, tag: str) -> dict[str, object]: ...

    def verify_release_asset(self, tag: str, path: Path) -> None: ...


class GitHubClient:
    """Small `gh` boundary that pins every request to public GitHub."""

    def __init__(
        self,
        *,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    ) -> None:
        self._runner = runner

    def _run(
        self,
        arguments: list[str],
        *,
        input_bytes: bytes | None = None,
        max_stdout_bytes: int = MAX_API_JSON_BYTES,
    ) -> bytes:
        command = ["gh", *arguments]
        with (
            tempfile.SpooledTemporaryFile(max_size=max_stdout_bytes + 1) as stdout_file,
            tempfile.SpooledTemporaryFile(max_size=64 * 1024) as stderr_file,
        ):
            try:
                completed = self._runner(
                    command,
                    input=input_bytes,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    timeout=COMMAND_TIMEOUT_SECONDS,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise CommandFailure("GitHub CLI command did not complete") from error
            captured_stdout = completed.stdout
            if captured_stdout is None:
                stdout_file.seek(0)
                captured_stdout = stdout_file.read(max_stdout_bytes + 1)
        if completed.returncode != 0:
            # Do not echo stderr: authentication helpers and proxies are outside
            # this script's control and may put sensitive values there.
            raise CommandFailure("GitHub CLI command failed")
        stdout = captured_stdout
        if isinstance(stdout, str):
            stdout = stdout.encode("utf-8")
        if stdout is None or len(stdout) > max_stdout_bytes:
            raise CommandFailure("GitHub CLI response exceeded the safety limit")
        return stdout

    def _api_json(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, object] | None = None,
    ) -> object:
        arguments = [
            "api",
            "--hostname",
            PUBLIC_GITHUB_HOST,
            "--method",
            method,
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
            path,
        ]
        input_bytes = None
        if body is not None:
            arguments.extend(("--input", "-"))
            input_bytes = json.dumps(
                body, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
        encoded = self._run(arguments, input_bytes=input_bytes)
        try:
            return json.loads(encoded)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise CommandFailure("GitHub API returned invalid JSON") from error

    def immutable_release_settings(self) -> dict[str, object]:
        document = self._api_json(
            "GET", f"repos/{release_manifest.REPOSITORY}/immutable-releases"
        )
        if not isinstance(document, dict):
            raise CommandFailure("immutable-release settings response is invalid")
        return document

    def release_tag_ruleset(self) -> dict[str, object]:
        document = self._api_json(
            "GET",
            f"repos/{release_manifest.REPOSITORY}/rulesets/{RELEASE_TAG_RULESET_ID}",
        )
        if not isinstance(document, dict):
            raise CommandFailure("release-tag ruleset response is invalid")
        return document

    def tag_ref(self, tag: str) -> dict[str, object]:
        document = self._api_json(
            "GET", f"repos/{release_manifest.REPOSITORY}/git/ref/tags/{tag}"
        )
        if not isinstance(document, dict):
            raise CommandFailure("tag ref response is invalid")
        return document

    def tagged_commit(self, tag: str) -> str:
        document = self._api_json(
            "GET", f"repos/{release_manifest.REPOSITORY}/commits/{tag}"
        )
        if not isinstance(document, dict) or not isinstance(document.get("sha"), str):
            raise CommandFailure("tagged commit response is invalid")
        return document["sha"]

    def list_releases_page(self, page: int) -> list[dict[str, object]]:
        document = self._api_json(
            "GET",
            f"repos/{release_manifest.REPOSITORY}/releases"
            f"?per_page={RELEASES_PER_PAGE}&page={page}",
        )
        if not isinstance(document, list) or not all(
            isinstance(item, dict) for item in document
        ):
            raise CommandFailure("release-list response is invalid")
        return document

    def release_by_id(self, release_id: int) -> dict[str, object]:
        document = self._api_json(
            "GET", f"repos/{release_manifest.REPOSITORY}/releases/{release_id}"
        )
        if not isinstance(document, dict):
            raise CommandFailure("release response is invalid")
        return document

    def verify_artifact_attestation(
        self, path: Path, *, tag: str, source_commit: str
    ) -> None:
        self._run(
            [
                "attestation",
                "verify",
                str(path),
                "--hostname",
                PUBLIC_GITHUB_HOST,
                "--repo",
                release_manifest.REPOSITORY,
                "--signer-workflow",
                f"{HOSTED_REPOSITORY}/{release_manifest.RELEASE_WORKFLOW}",
                "--source-ref",
                f"refs/tags/{tag}",
                "--source-digest",
                source_commit,
                "--deny-self-hosted-runners",
            ],
            max_stdout_bytes=MAX_ATTESTATION_JSON_BYTES,
        )

    def publish_release(self, release_id: int, *, make_latest: str) -> None:
        document = self._api_json(
            "PATCH",
            f"repos/{release_manifest.REPOSITORY}/releases/{release_id}",
            body={"draft": False, "make_latest": make_latest},
        )
        if not isinstance(document, dict):
            raise CommandFailure("release publication response is invalid")

    def verify_release_attestation(self, tag: str) -> dict[str, object]:
        encoded = self._run(
            [
                "release",
                "verify",
                tag,
                "--repo",
                HOSTED_REPOSITORY,
                "--format",
                "json",
            ],
            max_stdout_bytes=MAX_ATTESTATION_JSON_BYTES,
        )
        try:
            document = json.loads(encoded)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise CommandFailure("release attestation response is invalid") from error
        if not isinstance(document, dict):
            raise CommandFailure("release attestation response is invalid")
        return document

    def verify_release_asset(self, tag: str, path: Path) -> None:
        self._run(
            [
                "release",
                "verify-asset",
                tag,
                str(path),
                "--repo",
                HOSTED_REPOSITORY,
            ],
            max_stdout_bytes=MAX_ATTESTATION_JSON_BYTES,
        )


@dataclass(frozen=True)
class BundleIdentity:
    dist: Path
    version: str
    tag: str
    source_commit: str
    tag_ref_digest: str
    prerelease: bool
    asset_names: tuple[str, ...]


@dataclass(frozen=True)
class ReleaseContext:
    bundle: BundleIdentity
    release_id: int
    state: str


def validate_local_environment(environment: Mapping[str, str]) -> None:
    """Reject variables that can silently replace the maintainer's keyring auth."""

    for variable in ("GH_TOKEN", "GITHUB_TOKEN"):
        if environment.get(variable):
            raise ValueError(
                f"{variable} must be unset; use the maintainer's `gh auth` login"
            )
    host = environment.get("GH_HOST")
    if host and host != PUBLIC_GITHUB_HOST:
        raise ValueError(f"GH_HOST must be unset or exactly {PUBLIC_GITHUB_HOST}")


def load_bundle_identity(*, dist: Path, expected_tag: str) -> BundleIdentity:
    manifest_path = dist / release_manifest.MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("release manifest must be a regular file")
    with manifest_path.open("rb") as source:
        encoded = source.read(release_manifest.MAX_MANIFEST_BYTES + 1)
        if len(encoded) > release_manifest.MAX_MANIFEST_BYTES or source.read(1):
            raise ValueError("release manifest exceeds the 64 KiB limit")
    try:
        document = json.loads(encoded)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("release manifest must be valid JSON") from error
    if not isinstance(document, dict):
        raise ValueError("release manifest must be a JSON object")

    version = document.get("version")
    tag = document.get("tag")
    source_commit = document.get("source_commit")
    tag_ref_digest = document.get("tag_ref_digest")
    repository = document.get("repository")
    channel = document.get("release_channel")
    if not all(
        isinstance(value, str)
        for value in (version, tag, source_commit, tag_ref_digest, repository, channel)
    ):
        raise ValueError("release manifest identity fields must be strings")
    if repository != release_manifest.REPOSITORY:
        raise ValueError("release manifest repository is not canonical")
    if tag != expected_tag:
        raise ValueError("explicit tag does not match the release manifest")
    expected_channel = release_manifest.release_channel(version)
    if tag != f"v{version}" or channel != expected_channel:
        raise ValueError("release manifest version, tag, and channel do not agree")
    if release_manifest.SOURCE_COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise ValueError("release manifest source commit is invalid")
    if release_manifest.SOURCE_COMMIT_PATTERN.fullmatch(tag_ref_digest) is None:
        raise ValueError("release manifest tag ref digest is invalid")

    local = verify_release.verify_local_bundle(
        dist=dist,
        version=version,
        source_commit=source_commit,
        tag_ref_digest=tag_ref_digest,
    )
    return BundleIdentity(
        dist=dist.resolve(strict=True),
        version=version,
        tag=tag,
        source_commit=source_commit,
        tag_ref_digest=tag_ref_digest,
        prerelease=expected_channel == "preview",
        asset_names=tuple(sorted(local)),
    )


def list_matching_releases(
    client: GitHubClientProtocol, tag: str
) -> list[dict[str, object]]:
    """Completely and boundedly list push-visible releases for one tag."""

    matches: list[dict[str, object]] = []
    seen_ids: set[int] = set()
    for page in range(1, MAX_RELEASE_PAGES + 1):
        releases = client.list_releases_page(page)
        if len(releases) > RELEASES_PER_PAGE:
            raise ValueError("release page exceeds the requested page size")
        for release in releases:
            if not isinstance(release, dict):
                raise ValueError("release list contains a non-object entry")
            release_id = release.get("id")
            if (
                isinstance(release_id, bool)
                or not isinstance(release_id, int)
                or release_id < 1
            ):
                raise ValueError("release list contains an invalid release ID")
            if release_id in seen_ids:
                raise ValueError("release listing changed during pagination")
            seen_ids.add(release_id)
            if release.get("tag_name") == tag:
                matches.append(release)
        if len(releases) < RELEASES_PER_PAGE:
            break
    else:
        raise ValueError("release listing reached the pagination limit")

    return matches


def find_unique_release(
    client: GitHubClientProtocol, tag: str
) -> dict[str, object]:
    """Return exactly one release after a complete bounded list operation."""

    matches = list_matching_releases(client, tag)
    if not matches:
        raise ValueError(f"no release exists for {tag}")
    if len(matches) != 1:
        raise ValueError(f"multiple releases exist for {tag}")
    return matches[0]


class Publisher:
    def __init__(
        self,
        client: GitHubClientProtocol,
        *,
        sleep: Callable[[float], None] = time.sleep,
        reconcile_attempts: int = DEFAULT_RECONCILE_ATTEMPTS,
        verification_attempts: int = DEFAULT_VERIFICATION_ATTEMPTS,
    ) -> None:
        if reconcile_attempts < 1 or verification_attempts < 1:
            raise ValueError("retry counts must be positive")
        self.client = client
        self.sleep = sleep
        self.reconcile_attempts = reconcile_attempts
        self.verification_attempts = verification_attempts

    def _check_controls(self) -> None:
        settings = self.client.immutable_release_settings()
        if settings.get("enabled") is not True:
            raise ValueError("immutable releases must be enabled before publication")

        ruleset = self.client.release_tag_ruleset()
        ruleset_id = ruleset.get("id")
        if isinstance(ruleset_id, bool) or ruleset_id != RELEASE_TAG_RULESET_ID:
            raise ValueError("release-tag ruleset identity does not match")
        if ruleset.get("enforcement") != "active" or ruleset.get("target") != "tag":
            raise ValueError("release-tag ruleset is not active for tags")
        if (
            ruleset.get("source_type") != "Repository"
            or ruleset.get("source") != release_manifest.REPOSITORY
        ):
            raise ValueError("release-tag ruleset source does not match the repository")
        if ruleset.get("bypass_actors") != []:
            raise ValueError("release-tag ruleset must have no bypass actors")
        conditions = ruleset.get("conditions")
        if not isinstance(conditions, dict):
            raise ValueError("release-tag ruleset conditions are invalid")
        ref_name = conditions.get("ref_name")
        if not isinstance(ref_name, dict) or ref_name != {
            "include": ["refs/tags/v*"],
            "exclude": [],
        }:
            raise ValueError("release-tag ruleset ref scope does not match")
        rules = ruleset.get("rules")
        if not isinstance(rules, list) or not all(
            isinstance(rule, dict) and isinstance(rule.get("type"), str)
            for rule in rules
        ):
            raise ValueError("release-tag ruleset rules are invalid")
        if len(rules) != 2 or {rule["type"] for rule in rules} != {
            "update",
            "deletion",
        }:
            raise ValueError("release-tag ruleset must block updates and deletions")

    def _check_tag(self, bundle: BundleIdentity) -> None:
        ref = self.client.tag_ref(bundle.tag)
        ref_object = ref.get("object")
        if not isinstance(ref_object, dict):
            raise ValueError("tag ref object is invalid")
        raw_digest = ref_object.get("sha")
        ref_type = ref_object.get("type")
        if raw_digest != bundle.tag_ref_digest or ref_type != "tag":
            raise ValueError("live raw tag ref does not match the attested manifest")
        tagged_commit = self.client.tagged_commit(bundle.tag)
        if tagged_commit != bundle.source_commit:
            raise ValueError("live peeled tag commit does not match the manifest")

    @staticmethod
    def _release_id(release: dict[str, object]) -> int:
        release_id = release.get("id")
        if isinstance(release_id, bool) or not isinstance(release_id, int):
            raise ValueError("release ID must be an integer")
        if release_id < 1:
            raise ValueError("release ID must be positive")
        return release_id

    @staticmethod
    def _release_state(
        release: dict[str, object],
        bundle: BundleIdentity,
        *,
        allow_mutable: bool = False,
    ) -> str:
        draft = release.get("draft")
        immutable = release.get("immutable")
        if draft is False and immutable is False:
            verify_release.verify_release_assets(
                release=release,
                dist=bundle.dist,
                version=bundle.version,
                source_commit=bundle.source_commit,
                tag_ref_digest=bundle.tag_ref_digest,
                expected_prerelease=bundle.prerelease,
            )
            published_at = release.get("published_at")
            if not isinstance(published_at, str) or not published_at:
                raise ValueError("public mutable release has no publication timestamp")
            if allow_mutable:
                return "mutable"
            raise RuntimeError(
                "CRITICAL: the release is PUBLIC but not immutable; "
                "do not retry publication"
            )
        if draft is True:
            stage = "draft"
            state = "draft"
        elif draft is False and immutable is True:
            stage = "published"
            state = "immutable"
        else:
            raise ValueError("release lifecycle state is invalid")
        verify_release.verify_release(
            release=release,
            dist=bundle.dist,
            version=bundle.version,
            source_commit=bundle.source_commit,
            tag_ref_digest=bundle.tag_ref_digest,
            expected_prerelease=bundle.prerelease,
            stage=stage,
        )
        return state

    def _verify_artifacts(self, bundle: BundleIdentity) -> None:
        for name in bundle.asset_names:
            path = bundle.dist / name
            last_error: Exception | None = None
            for attempt in range(self.verification_attempts):
                try:
                    self.client.verify_artifact_attestation(
                        path,
                        tag=bundle.tag,
                        source_commit=bundle.source_commit,
                    )
                    break
                except CommandFailure as error:
                    last_error = error
                    if attempt + 1 < self.verification_attempts:
                        self.sleep(3)
            else:
                raise RuntimeError(
                    f"artifact attestation could not be verified: {name}"
                ) from last_error

    def _verify_postpublication(self, context: ReleaseContext) -> None:
        bundle = context.bundle
        last_error: Exception | None = None
        for attempt in range(self.verification_attempts):
            try:
                attestation = self.client.verify_release_attestation(bundle.tag)
                verify_release.verify_release_attestation(
                    attestation=attestation,
                    dist=bundle.dist,
                    version=bundle.version,
                    source_commit=bundle.source_commit,
                    tag_ref_digest=bundle.tag_ref_digest,
                )
                break
            except (CommandFailure, OSError, ValueError) as error:
                last_error = error
                if attempt + 1 < self.verification_attempts:
                    self.sleep(3)
        else:
            raise RuntimeError(
                "immutable release attestation could not be verified"
            ) from last_error

        for name in bundle.asset_names:
            last_error = None
            for attempt in range(self.verification_attempts):
                try:
                    self.client.verify_release_asset(bundle.tag, bundle.dist / name)
                    break
                except CommandFailure as error:
                    last_error = error
                    if attempt + 1 < self.verification_attempts:
                        self.sleep(2)
            else:
                raise RuntimeError(
                    f"release asset attestation could not be verified: {name}"
                ) from last_error

        self._check_tag(bundle)
        final_release = self.client.release_by_id(context.release_id)
        if self._release_id(final_release) != context.release_id:
            raise ValueError("final release readback changed identity")
        if self._release_state(final_release, bundle) != "immutable":
            raise RuntimeError("final release readback is not immutable")

    def preflight(self, *, dist: Path, expected_tag: str) -> ReleaseContext:
        bundle = load_bundle_identity(dist=dist, expected_tag=expected_tag)
        self._check_controls()
        self._check_tag(bundle)
        release = find_unique_release(self.client, bundle.tag)
        context = ReleaseContext(
            bundle=bundle,
            release_id=self._release_id(release),
            state=self._release_state(release, bundle),
        )
        self._verify_artifacts(bundle)
        if context.state == "immutable":
            self._verify_postpublication(context)
        return context

    def verify_ci_draft(self, *, dist: Path, expected_tag: str) -> ReleaseContext:
        bundle = load_bundle_identity(dist=dist, expected_tag=expected_tag)
        self._check_tag(bundle)
        release = find_unique_release(self.client, bundle.tag)
        context = ReleaseContext(
            bundle=bundle,
            release_id=self._release_id(release),
            state=self._release_state(release, bundle),
        )
        if context.state != "draft":
            raise ValueError("CI staging requires an unpublished draft")
        self._verify_artifacts(bundle)
        return context

    def verify_ci_absent(self, *, dist: Path, expected_tag: str) -> BundleIdentity:
        bundle = load_bundle_identity(dist=dist, expected_tag=expected_tag)
        self._check_tag(bundle)
        if list_matching_releases(self.client, bundle.tag):
            raise ValueError(
                f"release {bundle.tag} already exists; "
                "published artifacts are never replaced"
            )
        return bundle

    def _revalidate(self, context: ReleaseContext) -> ReleaseContext:
        bundle = context.bundle
        # Attestation lookup can wait for eventual consistency. Run it before
        # the final live control/tag/draft reads so those checks directly guard
        # the single publication write.
        self._verify_artifacts(bundle)
        self._check_controls()
        self._check_tag(bundle)
        listed = find_unique_release(self.client, bundle.tag)
        if self._release_id(listed) != context.release_id:
            raise ValueError("release identity changed after preflight")
        listed_state = self._release_state(listed, bundle)
        return ReleaseContext(bundle, context.release_id, listed_state)

    def _reconcile(self, context: ReleaseContext) -> ReleaseContext:
        saw_exact_draft = False
        saw_exact_mutable = False
        last_observation = "unknown"
        last_read_error: Exception | None = None
        for attempt in range(self.reconcile_attempts):
            try:
                matches = list_matching_releases(self.client, context.bundle.tag)
                if not matches:
                    raise CommandFailure(
                        "release is temporarily absent from list readback"
                    )
                if len(matches) != 1:
                    raise ValueError("multiple releases appeared during publication")
                release = matches[0]
                if self._release_id(release) != context.release_id:
                    raise ValueError("publication readback changed release identity")
                state = self._release_state(
                    release, context.bundle, allow_mutable=True
                )
                if state == "immutable":
                    immutable_context = ReleaseContext(
                        context.bundle, context.release_id, "immutable"
                    )
                    self._verify_postpublication(immutable_context)
                    return immutable_context
                if state == "draft":
                    saw_exact_draft = True
                    last_observation = "draft"
                else:
                    saw_exact_mutable = True
                    last_observation = "mutable"
            except CommandFailure as error:
                last_read_error = error
                last_observation = "unknown"
            if attempt + 1 < self.reconcile_attempts:
                self.sleep(3)
        if saw_exact_mutable:
            raise RuntimeError(
                "CRITICAL: the release is PUBLIC but not immutable after the deadline; "
                "do not retry publication"
            )
        if saw_exact_draft and last_observation == "draft":
            raise RuntimeError(
                "publication did not complete; the exact release remains "
                "an unpublished draft"
            )
        raise RuntimeError(
            "publication outcome is unknown; inspect the exact release ID "
            "before any retry"
        ) from last_read_error

    def publish(self, context: ReleaseContext) -> ReleaseContext:
        current = self._revalidate(context)
        if current.state == "immutable":
            self._verify_postpublication(current)
            return current

        make_latest = "false" if current.bundle.prerelease else "true"
        try:
            # This is the only write. It is intentionally never retried because
            # a timeout may mean GitHub committed the state transition.
            self.client.publish_release(current.release_id, make_latest=make_latest)
        except CommandFailure:
            pass
        return self._reconcile(current)


def _print_summary(context: ReleaseContext, *, ci: bool = False) -> None:
    bundle = context.bundle
    heading = "CI draft verification passed" if ci else "Release preflight passed"
    print(heading)
    print(f"repository: {release_manifest.REPOSITORY}")
    print(f"tag: {bundle.tag}")
    print(f"source_commit: {bundle.source_commit}")
    print(f"tag_ref_digest: {bundle.tag_ref_digest}")
    print(f"release_id: {context.release_id}")
    print(f"release_state: {context.state}")
    print(f"asset_count: {len(bundle.asset_names)}")
    if ci:
        print("immutable_release_setting: not checked; local preflight required")
        print("release_tag_ruleset: not checked; local preflight required")
    else:
        print("immutable_release_setting: enabled")
        print(f"release_tag_ruleset: {RELEASE_TAG_RULESET_ID}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--publish",
        action="store_true",
        help="perform the single irreversible draft-to-published transition",
    )
    parser.add_argument(
        "--ci-verify-draft", action="store_true", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--ci-assert-absent", action="store_true", help=argparse.SUPPRESS
    )
    arguments = parser.parse_args()
    selected_modes = sum(
        (arguments.publish, arguments.ci_verify_draft, arguments.ci_assert_absent)
    )
    if selected_modes > 1:
        parser.error("publication and CI modes are mutually exclusive")

    try:
        publisher = Publisher(GitHubClient())
        if arguments.ci_verify_draft or arguments.ci_assert_absent:
            if os.environ.get("GITHUB_ACTIONS") != "true":
                raise ValueError(
                    "CI release verification is restricted to GitHub Actions"
                )
            if os.environ.get("GITHUB_REPOSITORY") != release_manifest.REPOSITORY:
                raise ValueError(
                    "CI draft verification is restricted to the canonical repo"
                )
            if arguments.ci_assert_absent:
                bundle = publisher.verify_ci_absent(
                    dist=arguments.dist, expected_tag=arguments.tag
                )
                print(
                    f"No GitHub Release exists for {bundle.tag}; "
                    "draft creation is safe."
                )
                return 0
            context = publisher.verify_ci_draft(
                dist=arguments.dist, expected_tag=arguments.tag
            )
            _print_summary(context, ci=True)
            return 0

        validate_local_environment(os.environ)
        context = publisher.preflight(dist=arguments.dist, expected_tag=arguments.tag)
        _print_summary(context)
        if not arguments.publish:
            if context.state == "draft":
                print("No public release exists. Re-run with --publish after review.")
            else:
                print("The immutable release is already fully verified.")
            return 0
        published = publisher.publish(context)
        print(
            f"Release {published.bundle.tag} is public, immutable, and fully verified."
        )
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
