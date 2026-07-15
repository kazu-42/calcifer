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
matrix without publishing:

```console
gh workflow run release.yml --repo kazu-42/calcifer --ref main
run_id="$(gh run list --repo kazu-42/calcifer --workflow release.yml \
  --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId')"
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
2. Merge only after protected-branch checks pass.
3. Run the release workflow manually on `main` and inspect all five native
   builds and the assembled `release-bundle` artifact.
4. Create an annotated tag on the exact reviewed `main` commit. The value of
   `version` must match `Cargo.toml` exactly:

   ```console
   version=0.1.0-alpha.4
   git fetch origin main --tags
   git switch main
   git pull --ff-only origin main
   git tag -a "v${version}" -m "Calcifer v${version}"
   git push origin "refs/tags/v${version}"
   ```

5. Watch the tag-triggered workflow. Its final job must be
   **Stage draft GitHub Release**; no public release exists yet:

   ```console
   run_id="$(gh run list --repo kazu-42/calcifer --workflow release.yml \
     --event push --limit 1 --json databaseId --jq '.[0].databaseId')"
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
   clean directory and check `SHA256SUMS`. On macOS use
   `shasum -a 256 -c SHA256SUMS`; elsewhere use
   `sha256sum --check SHA256SUMS`.

   ```console
   verify_dir="$(mktemp -d)"
   gh release download "v${version}" --repo github.com/kazu-42/calcifer \
     --dir "$verify_dir"
   (cd "$verify_dir" && \
     if command -v sha256sum >/dev/null; then \
       sha256sum --check SHA256SUMS; \
     else \
       shasum -a 256 -c SHA256SUMS; \
     fi)
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
tar -xzf calcifer-v0.1.0-alpha.3-<target>.tar.gz
install -d "$HOME/.local/bin"
install -m 0755 calcifer-v0.1.0-alpha.3-<target>/calcifer "$HOME/.local/bin/calcifer"
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

If an artifact or the release pipeline itself is compromised, stop new
downloads through the audited emergency-removal procedure above, open a public
incident or private security advisory as appropriate, and publish a new version
from a reviewed commit. Record what was removed and why; do not reuse the
compromised version number or tag.
