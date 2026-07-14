# Releasing Calcifer

Calcifer publishes pre-alpha binaries through a tag-driven GitHub Actions
workflow. A manual workflow run is always a dry run: only a matching version
tag **push event** can enter the publish job, even when manual dispatch selects a
tag ref.

## Release guarantees

The release workflow enforces these boundaries:

- The tag must exactly match the Calcifer version in `Cargo.toml`.
- The tagged commit must be reachable from `main`.
- The five branch-protection checks must have completed successfully for the
  tagged commit.
- The repository quality gate runs again before release builds start.
- Every target is built on a native GitHub-hosted runner; the completed archive
  is extracted there and its packaged binary is smoke-tested.
- Archive names and archive metadata are deterministic, and the final bundle
  includes `SHA256SUMS`.
- GitHub records build-provenance attestations for every published asset.
- A workflow rerun refuses to replace an existing GitHub Release.

This is a reproducible release *process*. Calcifer does not yet claim that Rust
linker output is bit-for-bit reproducible across separate runner instances.

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
4. Create an annotated tag on the exact reviewed `main` commit:

   ```console
   git fetch origin main --tags
   git switch main
   git pull --ff-only origin main
   git tag -a v0.1.0-alpha.3 -m "Calcifer v0.1.0-alpha.3"
   git push origin refs/tags/v0.1.0-alpha.3
   ```

5. Watch the tag-triggered workflow and inspect the published pre-release:

   ```console
   gh run list --repo kazu-42/calcifer --workflow release.yml --limit 5
   gh release view v0.1.0-alpha.3 --repo kazu-42/calcifer
   ```

6. Download the assets into a clean directory and verify both checksums and at
   least one artifact attestation:

   ```console
   gh release download v0.1.0-alpha.3 --repo kazu-42/calcifer
   sha256sum --check SHA256SUMS
   gh attestation verify \
     calcifer-v0.1.0-alpha.3-x86_64-unknown-linux-gnu.tar.gz \
     --repo kazu-42/calcifer
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

Published assets are never silently replaced. If a functional regression is
found, leave the release available, mark it clearly in the release notes, and
publish a higher version containing the fix. Users can reinstall a previously
verified artifact while their profile state remains in place.

If an artifact or the release pipeline itself is compromised, stop new
downloads by removing the affected GitHub Release and tag, open a public
incident or private security advisory as appropriate, and publish a new version
from a reviewed commit. Record what was removed and why; do not reuse the
compromised version number.
