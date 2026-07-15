# Releasing Calcifer

Calcifer publishes pre-alpha binaries through a tag-driven GitHub Actions
workflow. A manual workflow run is always a dry run: only a matching version
tag **push event** can enter the publish job, even when manual dispatch selects a
tag ref.

## Release guarantees

The release workflow enforces these boundaries:

- The tag must exactly match the Calcifer version in `Cargo.toml`.
- Tag-triggered publication is restricted to the canonical
  `kazu-42/calcifer` repository; a fork or repository transfer fails before
  building a public release until the manifest contract is deliberately
  updated.
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
- Before any write to a GitHub Release, the privileged job independently
  rebuilds the canonical manifest, validates every archive body and checksum,
  and verifies its expected `source_commit`.
- The publish job mints and verifies GitHub artifact attestations over the exact
  assembled release assets. These are release-workflow attestations, not
  separate statements emitted by each native build job.
- The workflow creates a draft, uploads every asset, and compares the GitHub
  API name, size, upload state, and SHA-256 readback with the local bundle.
- Only an exact draft is published. The workflow then requires an immutable
  API readback and verifies that the release attestation binds the exact asset
  set, tag, and pinned raw tag-ref digest before verifying every local asset.
  For the documented annotated tags, the raw tag-object SHA is distinct from
  the peeled source commit; the workflow pins and rechecks both.
- The active [Immutable release tags ruleset](https://github.com/kazu-42/calcifer/rules/18956764)
  has no bypass actors and blocks updates and deletions for every `v*` tag. The
  workflow also verifies both the raw tag ref and peeled commit immediately
  before draft creation and again immediately before publication.
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

5. Watch the tag-triggered workflow and inspect the published pre-release:

   ```console
   gh run list --repo kazu-42/calcifer --workflow release.yml --limit 5
   gh release view "v${version}" --repo kazu-42/calcifer
   ```

6. Download the assets into a clean directory and verify the release
   attestation, every checksum, and every asset attestation:

   ```console
   gh release download "v${version}" --repo kazu-42/calcifer
   sha256sum --check SHA256SUMS
   gh release verify "v${version}" --repo kazu-42/calcifer
   source_commit="$(gh api \
     "repos/kazu-42/calcifer/commits/v${version}" --jq .sha)"
   for asset in calcifer-* SHA256SUMS; do
     gh attestation verify "$asset" \
       --repo kazu-42/calcifer \
       --signer-workflow kazu-42/calcifer/.github/workflows/release.yml \
       --source-ref "refs/tags/v${version}" \
       --source-digest "$source_commit" \
       --deny-self-hosted-runners
     gh release verify-asset "v${version}" "$asset" --repo kazu-42/calcifer
   done
   ```

   On macOS, use `shasum -a 256 -c SHA256SUMS` for the checksum step.

7. Install one artifact on a clean supported host and run:

   ```console
   calcifer --version
   calcifer --help
   calcifer --json doctor
   ```

8. Only after a fixed release exists, update any corresponding draft security
   advisory with the patched version. Publishing an advisory remains a separate
   deliberate action.

## Failure and recovery boundaries

The draft is intentionally the only mutable phase. If upload or draft readback
fails, the workflow stops without publishing. It also refuses to reuse that
existing draft on a rerun. A maintainer must inspect the failure, delete only
the unpublished draft after confirming that no valid release exists, and then
rerun from the unchanged reviewed tag.

After publication, the release and tag are immutable. A failed post-publication
readback can be retried manually with `gh release verify` and
`gh release verify-asset`; it never authorizes changing an asset. If the
published bytes are wrong, ship a higher version. If the release is part of a
security incident, remove the release through the documented incident process,
record why, and never reuse its tag name or version.

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
