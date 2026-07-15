# Releasing Calcifer

Calcifer builds and stages pre-alpha binaries through a tag-driven GitHub
Actions workflow. The tag workflow deliberately stops at a verified draft. A
maintainer publishes that exact draft with a local, read-first command after
checking repository administration controls with the maintainer's existing
`gh` login. No administration token is stored in Actions.

A manual workflow run is always a build-only dry run. Only a matching version
tag **push event** can enter the draft-staging job, even when manual dispatch
selects a tag ref.

## Release guarantees

The release workflow enforces these boundaries:

- The tag must exactly match the Calcifer version in `Cargo.toml`.
- The release tag must be an annotated Git tag object. Lightweight tags fail
  before draft creation and again during the local publication preflight.
- Tag-triggered draft staging is restricted to the canonical
  `kazu-42/calcifer` repository; a fork or repository transfer fails before
  writing a GitHub Release until the manifest contract is deliberately updated.
- The tagged commit must be reachable from `main`.
- The five branch-protection checks must have completed successfully for the
  tagged commit.
- The repository quality gate runs again before release builds start.
- Every target is built on a native GitHub-hosted runner; the completed archive
  is extracted there and its packaged binary is smoke-tested.
- Linux jobs prove that the native runner is on the supported glibc 2.35
  baseline and reject binaries whose highest required GLIBC symbol is newer.
- Archive names and archive metadata are deterministic. A canonical versioned
  manifest records the archive and in-archive binary SHA-256 for every target,
  and `SHA256SUMS` covers all five archives plus that manifest.
- Before any write to a GitHub Release draft, the privileged job independently
  rebuilds the canonical manifest, validates every archive body and checksum,
  and verifies its expected peeled `source_commit` and raw `tag_ref_digest`.
- The draft-staging job mints and verifies GitHub artifact attestations over the
  exact assembled release assets. These are release-workflow attestations, not
  separate statements emitted by each native build job.
- The workflow creates a draft, uploads every asset, and compares the GitHub
  List releases API name, size, upload state, and SHA-256 readback with the
  local bundle. A green tag workflow means "draft ready", not "published".
- `scripts/publish_release.py` is read-only by default. It rejects environment
  token or host redirection, requires public GitHub and the canonical repo,
  checks immutable releases and ruleset 18956764 with admin read access,
  completely and boundedly lists push-visible releases, and re-verifies the
  pinned tag, exact draft bytes, and every assembled-artifact attestation.
- Explicit `--publish` repeats those checks immediately before issuing one
  numeric release-ID `PATCH`. It never retries that write. Read-only
  reconciliation then requires an immutable API readback, exact release
  attestation, and every asset attestation.
- For documented annotated tags, the raw tag-object SHA is distinct from the
  peeled source commit. Both values are pinned in the artifact-attested
  manifest and rechecked immediately before publication.
- The active [Immutable release tags ruleset](https://github.com/kazu-42/calcifer/rules/18956764)
  has no bypass actors and blocks updates and deletions for every `v*` tag. The
  workflow verifies both values before draft creation; the local publisher
  repeats them before publication.
- A workflow rerun refuses to replace an existing GitHub Release.

This is a reproducible release *process*. Calcifer does not yet claim that Rust
linker output is bit-for-bit reproducible across separate runner instances.
The manifest contract is documented in [release-manifest.md](release-manifest.md).

## Supported artifacts

| Platform | Rust target | Archive |
| --- | --- | --- |
| Linux x86-64, glibc 2.35+ | `x86_64-unknown-linux-gnu` | `.tar.gz` |
| Linux ARM64, glibc 2.35+ | `aarch64-unknown-linux-gnu` | `.tar.gz` |
| macOS Intel | `x86_64-apple-darwin` | `.tar.gz` |
| macOS Apple silicon | `aarch64-apple-darwin` | `.tar.gz` |
| Windows x86-64 | `x86_64-pc-windows-msvc` | `.zip` |

The archives are not code-signed or notarized yet. GitHub artifact attestations
provide provenance, not an operating-system code-signing identity.

Linux artifacts are built natively on Ubuntu 22.04 to avoid accidentally
requiring Ubuntu 24.04's glibc 2.39. A future musl/static artifact can extend
support to older glibc distributions without weakening the current smoke tests.
The workflow records the runner version and highest required GLIBC symbol in
the job summary; a change beyond 2.35 fails instead of silently narrowing
compatibility.

## Dry run

After the release workflow exists on the default branch, run the complete build
matrix without publishing. Record the exact remote `main` commit first and
select only a workflow run for that SHA:

```console
git fetch origin main
release_commit="$(git rev-parse refs/remotes/origin/main)"
dispatched_after="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
gh workflow run release.yml --repo kazu-42/calcifer --ref main
run_json='[]'
for _ in {1..30}; do
  run_json="$(gh run list --repo kazu-42/calcifer --workflow release.yml \
    --event workflow_dispatch --commit "$release_commit" \
    --created ">=$dispatched_after" --limit 1 --json databaseId,headSha)"
  test "$(jq -r 'length' <<<"$run_json")" -eq 0 || break
  sleep 2
done
test "$(jq -r 'length' <<<"$run_json")" -eq 1
test "$(jq -r '.[0].headSha' <<<"$run_json")" = "$release_commit"
run_id="$(jq -r '.[0].databaseId' <<<"$run_json")"
gh run watch "$run_id" --repo kazu-42/calcifer --exit-status
```

Pull requests that change the workflow, packaging code, Cargo metadata, or the
Makefile also run the release matrix without any write or OIDC permissions.

## Maintainer checklist

1. Prepare a normal pull request that:
   - updates the version in `Cargo.toml` and `Cargo.lock`;
   - moves the relevant `CHANGELOG.md` entries into the matching release
     section;
   - updates compatibility or installation documentation when needed.
2. Merge only after protected-branch checks pass. Record the merged release PR's
   exact commit and verify the protected `main` CI run for that SHA. Replace
   `123` with the release-preparation PR number:

   ```console
   release_pr=123
   release_commit="$(gh pr view "$release_pr" --repo kazu-42/calcifer \
     --json mergeCommit,state \
     --jq 'select(.state == "MERGED") | .mergeCommit.oid')"
   test -n "$release_commit"
   git fetch origin main --tags
   git merge-base --is-ancestor "$release_commit" refs/remotes/origin/main
   ci_json="$(gh run list --repo kazu-42/calcifer --workflow ci.yml \
     --event push --commit "$release_commit" --limit 1 \
     --json databaseId,headSha)"
   test "$(jq -r 'length' <<<"$ci_json")" -eq 1
   test "$(jq -r '.[0].headSha' <<<"$ci_json")" = "$release_commit"
   ci_run_id="$(jq -r '.[0].databaseId' <<<"$ci_json")"
   gh run watch "$ci_run_id" --repo kazu-42/calcifer --exit-status
   ```

3. Require remote `main` to still equal that recorded commit, then run the
   release workflow manually and inspect all five native builds and the
   assembled `release-bundle` artifact. Select the run by commit, never by
   repository-wide recency:

   ```console
   git fetch origin main
   test "$(git rev-parse refs/remotes/origin/main)" = "$release_commit"
   dispatched_after="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
   gh workflow run release.yml --repo kazu-42/calcifer --ref main
   dry_run_json='[]'
   for _ in {1..30}; do
     dry_run_json="$(gh run list --repo kazu-42/calcifer --workflow release.yml \
       --event workflow_dispatch --commit "$release_commit" \
       --created ">=$dispatched_after" --limit 1 --json databaseId,headSha)"
     test "$(jq -r 'length' <<<"$dry_run_json")" -eq 0 || break
     sleep 2
   done
   test "$(jq -r 'length' <<<"$dry_run_json")" -eq 1
   test "$(jq -r '.[0].headSha' <<<"$dry_run_json")" = "$release_commit"
   dry_run_id="$(jq -r '.[0].databaseId' <<<"$dry_run_json")"
   gh run watch "$dry_run_id" --repo kazu-42/calcifer --exit-status
   ```

4. Create an annotated tag on the exact reviewed `main` commit. The value of
   `version` must match `Cargo.toml` exactly:

   ```console
   version=0.1.0-alpha.4
   git fetch origin main --tags
   git merge-base --is-ancestor "$release_commit" refs/remotes/origin/main
   git tag -a "v${version}" "$release_commit" -m "Calcifer v${version}"
   tag_pushed_after="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
   git push origin "refs/tags/v${version}"
   ```

5. Watch the tag-triggered workflow. Its final job must be
   **Stage draft GitHub Release**; no public release exists yet:

   ```console
   run_id=''
   for _ in {1..30}; do
     tag_run_json="$(gh run list --repo kazu-42/calcifer \
       --workflow release.yml --event push --commit "$release_commit" \
       --created ">=$tag_pushed_after" --limit 20 \
       --json databaseId,headBranch,headSha)"
     run_id="$(jq -r --arg tag "v${version}" --arg sha "$release_commit" \
       '[.[] | select(.headBranch == $tag and .headSha == $sha)] \
        | .[0].databaseId // empty' <<<"$tag_run_json")"
     test -z "$run_id" || break
     sleep 2
   done
   test -n "$run_id"
   gh run watch "$run_id" --repo kazu-42/calcifer --exit-status
   ```

6. From the reviewed repository checkout, download that run's attested bundle
   into a new directory. Ensure `GH_TOKEN` and `GITHUB_TOKEN` are unset so `gh`
   uses the maintainer's keyring login. Run the read-only preflight first, review
   its repo/tag/commit/release-ID/asset-count summary, then explicitly publish:

   ```console
   release_dir="$(mktemp -d)"
   gh run download "$run_id" --repo kazu-42/calcifer \
     --name release-bundle --dir "$release_dir"
   unset GH_TOKEN GITHUB_TOKEN
   gh auth status --hostname github.com
   python3 scripts/publish_release.py \
     --dist "$release_dir" --tag "v${version}"
   python3 scripts/publish_release.py \
     --dist "$release_dir" --tag "v${version}" --publish
   ```

   The second command performs exactly one draft-to-published write and returns
   success only after immutable release and per-asset attestations verify. For a
   stable version it marks the release latest; prereleases are never latest.

7. As an independent readback, download the now-public assets into another
   clean directory. The local verifier rejects a missing, duplicate, or
   unexpected asset and validates the canonical manifest and `SHA256SUMS`.
   Then verify both provenance layers for every one of the seven assets: the
   release-workflow artifact attestation and the immutable-release asset
   attestation. Finally verify the release attestation itself.

   ```console
   verify_dir="$(mktemp -d)"
   gh release download "v${version}" --repo github.com/kazu-42/calcifer \
     --dir "$verify_dir"
   tag_ref_digest="$(gh api --hostname github.com \
     "repos/kazu-42/calcifer/git/ref/tags/v${version}" --jq '.object.sha')"
   python3 scripts/verify_release.py \
     --dist "$verify_dir" \
     --version "$version" \
     --source-commit "$release_commit" \
     --tag-ref-digest "$tag_ref_digest" \
     --local-only
   for asset in "$verify_dir"/*; do
     gh attestation verify "$asset" \
       --hostname github.com \
       --repo kazu-42/calcifer \
       --signer-workflow \
         github.com/kazu-42/calcifer/.github/workflows/release.yml \
       --source-ref "refs/tags/v${version}" \
       --source-digest "$release_commit" \
       --deny-self-hosted-runners >/dev/null
     gh release verify-asset "v${version}" "$asset" \
       --repo github.com/kazu-42/calcifer >/dev/null
   done
   gh release verify "v${version}" --repo github.com/kazu-42/calcifer
   ```

8. Install one artifact on a clean supported host and run:

   ```console
   calcifer --version
   calcifer --help
   calcifer --json doctor
   ```

9. Only after a fixed release exists, update any corresponding draft security
   advisory with the patched version. Publishing an advisory remains a separate
   deliberate action.

## Failure and recovery boundaries

The draft is intentionally the only mutable phase. If upload or draft readback
fails, the workflow stops without publishing. It also refuses to reuse an
existing draft on rerun. A maintainer must inspect the failed run and the
push-visible release list, delete only the unpublished draft after confirming
its exact numeric ID and that no public release exists, then rerun from the
unchanged reviewed tag.

A failed local preflight performs no write. Correct the repository setting,
ruleset, authentication, bundle, or tag problem and run the read-only command
again. Do not work around a failure with `GH_TOKEN`, `GITHUB_TOKEN`, a PAT
stored in Actions, or a different GitHub host.

The publication `PATCH` is never retried, including after a timeout. The command
uses read-only List releases reconciliation against the same tag and numeric
release ID:

- If the exact draft remains unpublished through the deadline, inspect it and
  then the full preflight may be run again.
- If the exact release is immutable, the command verifies release and asset
  attestations and succeeds even when the original write returned an error.
- A transient public-but-not-yet-immutable readback is polled read-only. If it
  persists through the deadline, treat it as a critical release incident; do
  not publish, edit, delete, or rerun blindly.
- If GitHub cannot provide a conclusive readback, the state is unknown. Inspect
  the exact release ID manually before any retry.

After publication, the release and tag are immutable. A failed post-publication
attestation check can be retried by running the default publisher command: an
already immutable release enters verification-only mode and issues no `PATCH`.
It never authorizes changing an asset. If the published bytes are wrong, ship a
higher version. If the release is part of a security incident, remove it
through the documented incident process, record why, and never reuse its tag
name or version.

## Release-tag protection and emergency removal

The [Immutable release tags ruleset](https://github.com/kazu-42/calcifer/rules/18956764)
is an independent guard during the mutable draft window: tag creation is
allowed, but no actor can update or delete a matching `v*` tag while the
ruleset is active. GitHub release immutability adds another guard after
publication: while an immutable release exists, its tag cannot be moved or
deleted and its assets cannot be replaced.

Normal regressions never justify removing a release or weakening either guard;
publish a higher version. Emergency removal is a manual, audited incident
operation and is intentionally not implemented by the release workflow:

1. Record the incident owner, reason, affected tag, commit, release-attestation
   readback, and asset digests before making changes.
2. Delete the affected immutable GitHub Release. This is required before GitHub
   permits deletion of its associated tag.
3. Have an administrator temporarily remove only the tag-deletion restriction
   from the no-bypass ruleset. Keep the update restriction active.
4. Delete the affected tag, then immediately restore the deletion restriction.
5. Read the live ruleset back and confirm that it is active, targets
   `refs/tags/v*`, blocks both updates and deletions, and has no bypass actors.
6. Publish a fixed higher version. A tag name formerly associated with an
   immutable release is never reused, even after release and tag deletion.

GitHub documents both the tag/asset lock and permanent tag-name reservation in
[Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
and the update/deletion semantics in
[Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

## Install and uninstall

On Linux or macOS, extract the archive for the current architecture and copy the
binary into a user-owned directory on `PATH`:

```console
version=0.1.0-alpha.4
# Choose the exact Rust target for this host from the supported-artifacts table.
target=x86_64-unknown-linux-gnu
prefix="calcifer-v${version}-${target}"
tar -xzf "${prefix}.tar.gz"
install -d "$HOME/.local/bin"
install -m 0755 "${prefix}/calcifer" "$HOME/.local/bin/calcifer"
```

On Windows, expand the `.zip` archive and place `calcifer.exe` in a user-owned
directory on `PATH`.

Uninstalling a binary release does not remove managed profiles:

```console
rm "$HOME/.local/bin/calcifer"
```

Delete profile state only through a future supported Calcifer command. Manual
state deletion can destroy sessions and credentials and is not a rollback step.

## Bad-release and rollback policy

Published assets are immutable and never silently replaced. If a functional
regression is found, leave the release available, document it separately, and
publish a higher version containing the fix. Users can reinstall a previously
verified artifact while their profile state remains in place.

Profile registry state is normally kept in the schema-v1 shape understood by
the published alpha.4 artifact. A newer Calcifer may temporarily replace that
file with a self-contained schema-v2 barrier while `auth remove` is in progress;
alpha.4 intentionally reports `invalid_registry` instead of writing through
that destructive state. If a rollback encounters that error, do not delete,
edit, or copy `profiles.json`, `removal.json`, or a `.removing-*` directory.
Run `auth list` once with the newer verified artifact that prepared the
transaction so bounded recovery can restore or finish stable schema-v1 state,
then verify `auth list` before reinstalling alpha.4. A completed removal or
pre-visibility rollback is directly alpha.4-readable.

If an artifact or the release pipeline itself is compromised, stop new
downloads through the audited emergency-removal procedure above, open a public
incident or private security advisory as appropriate, and publish a new version
from a reviewed commit. Record what was removed and why; do not reuse the
compromised version number or tag.
