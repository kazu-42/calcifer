# Release manifest v1

Every Calcifer release starting with the next published version contains
`calcifer-release-manifest-v1.json`. The manifest is a deterministic,
machine-readable contract between the native build jobs, the immutable GitHub
Release, package managers, and the read-only update checker.

The v1 file is UTF-8 JSON with keys sorted lexicographically, no insignificant
whitespace, and exactly one trailing newline. It cannot exceed 64 KiB. Its
top-level shape is:

```json
{
  "attestations": {
    "artifact": {
      "kind": "github_artifact_attestation",
      "job": "publish",
      "subjects": "release_assets",
      "workflow": ".github/workflows/release.yml"
    },
    "immutable_release": {
      "kind": "github_release_attestation",
      "required": true
    },
    "signer_workflow": {
      "repository": "kazu-42/calcifer",
      "workflow": ".github/workflows/release.yml"
    }
  },
  "product": "calcifer",
  "release_channel": "preview",
  "repository": "kazu-42/calcifer",
  "schema": "calcifer-release-manifest-v1",
  "source_commit": "40-character-lowercase-git-sha",
  "tag": "v0.1.0-alpha.4",
  "tag_ref_digest": "40-character-lowercase-raw-tag-object-sha",
  "targets": [],
  "version": "0.1.0-alpha.4"
}
```

`targets` contains exactly one entry, in Rust-target order, for each supported
artifact:

- `aarch64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `x86_64-pc-windows-msvc`
- `x86_64-unknown-linux-gnu`

Each target records `os`, `architecture`, optional `libc`, structured runtime
requirements, and these nested values:

```json
{
  "archive": {
    "format": "tar.gz",
    "name": "calcifer-v0.1.0-alpha.4-x86_64-unknown-linux-gnu.tar.gz",
    "sha256": "64-lowercase-hex-characters",
    "size": 123456
  },
  "binary": {
    "path": "calcifer-v0.1.0-alpha.4-x86_64-unknown-linux-gnu/calcifer",
    "sha256": "64-lowercase-hex-characters"
  }
}
```

The generator accepts only the five expected archives. It rejects symlinks,
special files, duplicate or unexpected entries, absolute paths, traversal,
unsafe separators, oversized archives, and layouts that differ from Calcifer's
packager. It fully reads every entry under bounded expanded-size and entry-count
limits instead of trusting archive metadata. ZIP validation checks the exact
container boundary and each entry CRC; tar.gz validation checks the complete
gzip stream, every declared entry body, and the deterministic zero-padded tar
tail. It streams and hashes the executable inside each archive instead of
trusting a descriptor produced by the build job.

`SHA256SUMS` covers the five archives and the manifest, in bytewise filename
order. The manifest does not contain its own digest; consumers verify its local
bytes against `SHA256SUMS` and the corresponding GitHub release-asset digest.
No download URL appears in the manifest. Consumers resolve an allowlisted asset
name only within the already selected GitHub Release.

## Version and channel invariants

- `tag` is exactly `v<version>`.
- A SemVer prerelease uses `release_channel: "preview"`; a version without a
  prerelease uses `release_channel: "stable"`.
- The GitHub Release prerelease flag must agree with that channel.
- `source_commit` is the exact tagged commit already required to be reachable
  from `main` and to have every protected check green.
- Release tags must be annotated Git tag objects. Lightweight tags fail before
  any draft is created and also fail the maintainer-local publication preflight.
- `tag_ref_digest` is the exact raw annotated-tag object SHA observed by the
  workflow, distinct from the peeled `source_commit`. It is inside the
  checksummed and artifact-attested manifest so the local publisher cannot
  establish a newer baseline.
- The active no-bypass release-tag ruleset rejects updates and deletions of
  every `v*` tag. The workflow pins both the raw tag-ref digest and the peeled
  `source_commit`, then rechecks both values before creating the draft. The
  maintainer-local publisher rechecks those same pinned values immediately
  before publishing it.
- A consumer that does not implement `calcifer-release-manifest-v1` must stop;
  it must not reinterpret a different schema as v1.

## Provenance semantics

The assembled-artifact attestation and immutable-release attestation are
separate claims. After the unprivileged native build outputs are assembled, the
privileged `publish` job (displayed as **Stage draft GitHub Release**) first
rebuilds and byte-compares this canonical manifest, validates `SHA256SUMS`, and
then mints an artifact attestation over
those exact downloaded bytes. This attests the assembled release assets and
release-workflow identity; it is not a distinct statement emitted by each
native build job. Publishing with immutable releases enabled then locks the tag
and assets and creates a second release attestation over the published set.

Before the draft exists, the workflow verifies every artifact attestation
against the repository, release workflow, tag ref, and `source_commit`. The tag
workflow then stops. The maintainer-local publisher downloads the attested
bundle, repeats every artifact-attestation verification, checks repository
immutability controls with admin-read access, and publishes the exact numeric
draft release ID once. After publication it verifies that the release
attestation names exactly the local asset set and binds the package subject to
the manifest's `tag_ref_digest`. That digest is the annotated tag-object SHA and
intentionally differs from the peeled `source_commit`.

Seeing attestation descriptors in the manifest is not local cryptographic
verification. A consumer must report separately whether attestations are
published, whether the downloaded manifest bytes matched their digest, and
whether an archive was actually downloaded and verified. The update checker
does not download an archive and therefore cannot claim to have locally
verified that archive.

## Credential-free update checking

`calcifer update check` defaults to the current binary's channel; `--channel
stable` and `--channel preview` select one explicitly. The command lists public
releases anonymously, parses every inspected tag as canonical SemVer, requires
the GitHub prerelease flag to agree with the selected channel, and chooses the
highest version only after completing a bounded release inventory. A missing
channel and an unsupported compile target are successful, explicit states. The
checker never falls back to a different architecture, libc, or Windows ABI.

For a selected release, the checker requires `immutable: true`, exactly the five
canonical archives plus this manifest and `SHA256SUMS`, uploaded state, bounded
sizes, canonical release/download URLs, and SHA-256 release-asset digests. It
downloads only the manifest and checksum assets. Their response bytes must
match the release-asset size/digest, the manifest must be canonical single-line
JSON in the exact v1 schema, and `SHA256SUMS` must be canonical, complete, and
agree with every manifest archive descriptor. The selected archive remains
metadata-only until a separate installer downloads and hashes it.

The anonymous HTTP client uses a fixed repository, fixed GitHub API version,
no authorization/cookie/proxy-authorization header, no token or profile lookup,
no endpoint override, no background polling, a ten-second per-request timeout,
four release pages of 100 entries, three redirects, a sixteen-asset preflight
cap, 1 MiB release pages, a 64 KiB manifest, and a 4 KiB checksum file.
Redirects remain HTTPS and may target only `api.github.com`, `github.com`,
`release-assets.githubusercontent.com`, or `objects.githubusercontent.com`;
compressed response bodies are rejected rather than expanded. An incomplete
inventory, network/rate-limit failure, unexpected redirect, schema drift,
mutable release, or digest mismatch is non-zero and never produces an update
recommendation.
