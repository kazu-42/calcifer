use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ureq::http::Uri;

use crate::cli::ReleaseChannelArgument;

const REPOSITORY: &str = "kazu-42/calcifer";
const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
const MANIFEST_SCHEMA: &str = "calcifer-release-manifest-v1";
const MANIFEST_NAME: &str = "calcifer-release-manifest-v1.json";
const CHECKSUM_NAME: &str = "SHA256SUMS";
const API_VERSION: &str = "2026-03-10";
const USER_AGENT: &str = concat!("calcifer/", env!("CARGO_PKG_VERSION"));
const API_ACCEPT: &str = "application/vnd.github+json";
const ASSET_ACCEPT: &str = "application/octet-stream";
const MAX_RELEASE_PAGES: u8 = 4;
const RELEASES_PER_PAGE: usize = 100;
const MAX_RELEASE_PAGE_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_CHECKSUM_BYTES: usize = 4 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RELEASE_ASSETS: usize = 16;
const MAX_REDIRECTS: usize = 3;
const MAX_REDIRECT_LOCATION_BYTES: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const SUPPORTED_TARGETS: [&str; 5] = [
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpdateError {
    Integrity,
    Network,
    PaginationLimit,
    RateLimited,
    RedirectRejected,
    ResponseTooLarge,
    Schema,
}

impl UpdateError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Integrity => "update_integrity_error",
            Self::Network => "update_network_error",
            Self::PaginationLimit => "update_pagination_limit",
            Self::RateLimited => "update_rate_limited",
            Self::RedirectRejected => "update_redirect_rejected",
            Self::ResponseTooLarge => "update_response_too_large",
            Self::Schema => "update_schema_error",
        }
    }

    pub(crate) const fn safe_message(self) -> &'static str {
        match self {
            Self::Integrity => {
                "The selected release failed Calcifer's immutable manifest or digest checks. Do not install it; retry later and report the release if the failure persists."
            }
            Self::Network => {
                "Calcifer could not fetch public release metadata from GitHub. Check connectivity and retry `calcifer update check`."
            }
            Self::PaginationLimit => {
                "GitHub returned more release pages than Calcifer can inspect safely. Use the releases page manually; Calcifer did not guess which version is latest."
            }
            Self::RateLimited => {
                "GitHub's anonymous rate limit prevented the update check. Wait for the limit to reset, then retry `calcifer update check`."
            }
            Self::RedirectRejected => {
                "GitHub returned a redirect outside Calcifer's fixed HTTPS allowlist. Do not install from that response; retry later."
            }
            Self::ResponseTooLarge => {
                "GitHub returned release metadata larger than Calcifer's safety limit. Do not install from that response; inspect the release manually."
            }
            Self::Schema => {
                "Published update metadata does not match Calcifer's strict v1 release contract. Do not install it; inspect or report the release."
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Channel {
    Stable,
    Preview,
}

impl Channel {
    const fn label(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
        }
    }
}

impl From<ReleaseChannelArgument> for Channel {
    fn from(value: ReleaseChannelArgument) -> Self {
        match value {
            ReleaseChannelArgument::Stable => Self::Stable,
            ReleaseChannelArgument::Preview => Self::Preview,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum UpdateStatus {
    NoReleaseInChannel,
    TargetUnsupported,
    UpToDate,
    UpdateAvailable,
}

impl UpdateStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::NoReleaseInChannel => "no release in channel",
            Self::TargetUnsupported => "target unsupported",
            Self::UpToDate => "up to date",
            Self::UpdateAvailable => "update available",
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct UpdateReport {
    schema_version: u8,
    command: &'static str,
    action: &'static str,
    ok: bool,
    status: UpdateStatus,
    channel: Channel,
    current_version: String,
    target: String,
    release: Option<ReleaseReport>,
    artifact: Option<ArtifactReport>,
    verification: Option<VerificationReport>,
    next_action: NextAction,
}

#[derive(Debug, Serialize)]
struct ReleaseReport {
    version: String,
    tag: String,
    url: String,
    immutable: bool,
    source_commit: String,
    tag_ref_digest: String,
}

#[derive(Debug, Serialize)]
struct ArtifactReport {
    target: String,
    name: String,
    url: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct VerificationReport {
    release_metadata: &'static str,
    manifest_bytes: &'static str,
    checksums_bytes: &'static str,
    selected_archive_bytes: &'static str,
    published_attestations: PublishedAttestations,
}

#[derive(Debug, Serialize)]
struct PublishedAttestations {
    artifact: AttestationEvidence,
    immutable_release: AttestationEvidence,
}

#[derive(Debug, Serialize)]
struct AttestationEvidence {
    kind: &'static str,
    publication: &'static str,
    locally_verified: bool,
}

#[derive(Debug, Serialize)]
struct NextAction {
    code: &'static str,
    message: String,
    url: Option<String>,
}

impl UpdateReport {
    pub(crate) fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub(crate) fn to_human(&self) -> String {
        let mut lines = vec![format!(
            "Calcifer {} · {} · {} ({})",
            self.current_version,
            self.target,
            self.status.label(),
            self.channel.label()
        )];
        if let Some(release) = &self.release {
            lines.push(format!(
                "Release {} ({}) · immutable",
                release.version, release.tag
            ));
        }
        if let Some(artifact) = &self.artifact {
            lines.push(format!(
                "Artifact {} · {} bytes · sha256:{}",
                artifact.name, artifact.size, artifact.sha256
            ));
        }
        if self.verification.is_some() {
            lines.push(
                "Published attestations: immutable release is published by GitHub; artifact attestation is declared by the manifest and was not locally verified."
                    .to_owned(),
            );
            lines.push(
                "Local bytes: manifest verified; SHA256SUMS verified; selected archive not downloaded."
                    .to_owned(),
            );
        }
        lines.push(format!("Next: {}", self.next_action.message));
        lines.join("\n")
    }

    fn target_unsupported(channel: Channel, current_version: &str, target: &str) -> Self {
        Self {
            schema_version: 1,
            command: "update",
            action: "check",
            ok: true,
            status: UpdateStatus::TargetUnsupported,
            channel,
            current_version: current_version.to_owned(),
            target: target.to_owned(),
            release: None,
            artifact: None,
            verification: None,
            next_action: NextAction {
                code: "build_from_source",
                message: format!(
                    "Build Calcifer from source for exact target {target}; no other ABI will be substituted."
                ),
                url: None,
            },
        }
    }

    fn no_release(channel: Channel, current_version: &str, target: &str) -> Self {
        Self {
            schema_version: 1,
            command: "update",
            action: "check",
            ok: true,
            status: UpdateStatus::NoReleaseInChannel,
            channel,
            current_version: current_version.to_owned(),
            target: target.to_owned(),
            release: None,
            artifact: None,
            verification: None,
            next_action: NextAction {
                code: "retry_later",
                message: format!(
                    "No immutable {} release is published; retry this channel later.",
                    channel.label()
                ),
                url: None,
            },
        }
    }
}

pub(crate) fn check(
    requested_channel: Option<ReleaseChannelArgument>,
) -> Result<UpdateReport, UpdateError> {
    let current_version = env!("CARGO_PKG_VERSION");
    let channel = match requested_channel {
        Some(channel) => channel.into(),
        None => channel_for_version(current_version)?,
    };
    let target = option_env!("CALCIFER_BUILD_TARGET").unwrap_or("unknown-compile-target");
    check_with(&HttpTransport::new(), channel, current_version, target)
}

fn check_with(
    transport: &impl Transport,
    channel: Channel,
    current_version: &str,
    target: &str,
) -> Result<UpdateReport, UpdateError> {
    let current = parse_version(current_version)?;
    if !SUPPORTED_TARGETS.contains(&target) {
        return Ok(UpdateReport::target_unsupported(
            channel,
            current_version,
            target,
        ));
    }

    let Some(selected) = select_release(transport, channel)? else {
        return Ok(UpdateReport::no_release(channel, current_version, target));
    };
    if !selected.immutable {
        return Err(UpdateError::Integrity);
    }

    let verified = verify_selected_release(transport, &selected, channel, target)?;
    let status = if selected.version > current {
        UpdateStatus::UpdateAvailable
    } else {
        UpdateStatus::UpToDate
    };
    let next_action = if status == UpdateStatus::UpdateAvailable {
        NextAction {
            code: "download_and_verify_archive",
            message: format!(
                "Download {} and verify sha256:{} before installation; this check did not download the archive.",
                verified.artifact.name, verified.artifact.sha256
            ),
            url: Some(verified.artifact.url.clone()),
        }
    } else {
        NextAction {
            code: "none",
            message: "No update is required for this channel and exact target.".to_owned(),
            url: None,
        }
    };

    Ok(UpdateReport {
        schema_version: 1,
        command: "update",
        action: "check",
        ok: true,
        status,
        channel,
        current_version: current_version.to_owned(),
        target: target.to_owned(),
        release: Some(ReleaseReport {
            version: selected.version.to_string(),
            tag: selected.tag_name,
            url: selected.html_url,
            immutable: true,
            source_commit: verified.source_commit,
            tag_ref_digest: verified.tag_ref_digest,
        }),
        artifact: Some(verified.artifact),
        verification: Some(VerificationReport {
            release_metadata: "verified_immutable",
            manifest_bytes: "verified",
            checksums_bytes: "verified",
            selected_archive_bytes: "not_downloaded",
            published_attestations: PublishedAttestations {
                artifact: AttestationEvidence {
                    kind: "github_artifact_attestation",
                    publication: "declared_by_manifest_not_queried",
                    locally_verified: false,
                },
                immutable_release: AttestationEvidence {
                    kind: "github_release_attestation",
                    publication: "published_by_github_immutable_release",
                    locally_verified: false,
                },
            },
        }),
        next_action,
    })
}

fn channel_for_version(version: &str) -> Result<Channel, UpdateError> {
    let version = parse_version(version)?;
    Ok(if version.pre.is_empty() {
        Channel::Stable
    } else {
        Channel::Preview
    })
}

fn parse_version(value: &str) -> Result<Version, UpdateError> {
    let version = Version::parse(value).map_err(|_| UpdateError::Schema)?;
    if !version.build.is_empty() || version.to_string() != value {
        return Err(UpdateError::Schema);
    }
    Ok(version)
}

#[derive(Debug)]
struct SelectedRelease {
    version: Version,
    tag_name: String,
    html_url: String,
    immutable: bool,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ApiRelease {
    id: u64,
    tag_name: String,
    html_url: String,
    draft: bool,
    prerelease: bool,
    immutable: bool,
    published_at: Option<String>,
    assets: Vec<ReleaseAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseAsset {
    id: u64,
    url: String,
    browser_download_url: String,
    name: String,
    state: String,
    size: u64,
    digest: Option<String>,
}

fn select_release(
    transport: &impl Transport,
    channel: Channel,
) -> Result<Option<SelectedRelease>, UpdateError> {
    let mut selected: Option<SelectedRelease> = None;
    let mut versions = BTreeSet::new();

    for page in 1..=MAX_RELEASE_PAGES {
        let url = format!(
            "https://api.github.com/repos/{REPOSITORY}/releases?per_page={RELEASES_PER_PAGE}&page={page}"
        );
        let body = fetch(transport, HttpRequest::api(url), MAX_RELEASE_PAGE_BYTES)?;
        let releases: Vec<ApiRelease> =
            serde_json::from_slice(&body).map_err(|_| UpdateError::Schema)?;
        if releases.len() > RELEASES_PER_PAGE {
            return Err(UpdateError::Schema);
        }
        let page_is_full = releases.len() == RELEASES_PER_PAGE;

        for release in releases {
            if release.id == 0
                || release.draft
                || release.published_at.as_deref().is_none_or(str::is_empty)
            {
                return Err(UpdateError::Schema);
            }
            let Some(version_text) = release.tag_name.strip_prefix('v') else {
                return Err(UpdateError::Schema);
            };
            let version = parse_version(version_text)?;
            let actual_channel = if version.pre.is_empty() {
                Channel::Stable
            } else {
                Channel::Preview
            };
            if release.prerelease != (actual_channel == Channel::Preview)
                || release.tag_name != format!("v{version}")
                || release.html_url
                    != format!(
                        "https://github.com/{REPOSITORY}/releases/tag/{}",
                        release.tag_name
                    )
                || !versions.insert(version.clone())
            {
                return Err(UpdateError::Schema);
            }
            if actual_channel == channel
                && selected
                    .as_ref()
                    .is_none_or(|candidate| version > candidate.version)
            {
                selected = Some(SelectedRelease {
                    version,
                    tag_name: release.tag_name,
                    html_url: release.html_url,
                    immutable: release.immutable,
                    assets: release.assets,
                });
            }
        }

        if !page_is_full {
            return Ok(selected);
        }
    }

    Err(UpdateError::PaginationLimit)
}

struct VerifiedRelease {
    source_commit: String,
    tag_ref_digest: String,
    artifact: ArtifactReport,
}

fn verify_selected_release(
    transport: &impl Transport,
    release: &SelectedRelease,
    channel: Channel,
    target: &str,
) -> Result<VerifiedRelease, UpdateError> {
    if release.assets.len() > MAX_RELEASE_ASSETS {
        return Err(UpdateError::Schema);
    }
    let expected_names = expected_asset_names(&release.version);
    let mut assets = BTreeMap::new();
    for asset in &release.assets {
        validate_api_asset(asset, release)?;
        if assets.insert(asset.name.clone(), asset).is_some() {
            return Err(UpdateError::Schema);
        }
    }
    if assets.keys().cloned().collect::<BTreeSet<_>>() != expected_names {
        return Err(UpdateError::Integrity);
    }

    let manifest_asset = assets.get(MANIFEST_NAME).ok_or(UpdateError::Integrity)?;
    let checksum_asset = assets.get(CHECKSUM_NAME).ok_or(UpdateError::Integrity)?;
    let manifest_bytes = download_asset(transport, manifest_asset, MAX_MANIFEST_BYTES)?;
    let checksum_bytes = download_asset(transport, checksum_asset, MAX_CHECKSUM_BYTES)?;
    let manifest = parse_manifest(&manifest_bytes)?;
    validate_manifest(&manifest, release, channel)?;
    let mut expected_checksum_names = expected_names.clone();
    expected_checksum_names.remove(CHECKSUM_NAME);
    let checksums = parse_checksums(&checksum_bytes, &expected_checksum_names)?;

    let manifest_digest = sha256_hex(&manifest_bytes);
    if checksums.get(MANIFEST_NAME) != Some(&manifest_digest) {
        return Err(UpdateError::Integrity);
    }

    for descriptor in &manifest.targets {
        let asset = assets
            .get(&descriptor.archive.name)
            .ok_or(UpdateError::Integrity)?;
        let checksum = checksums
            .get(&descriptor.archive.name)
            .ok_or(UpdateError::Integrity)?;
        if checksum != &descriptor.archive.sha256
            || asset_digest(asset)? != descriptor.archive.sha256
            || asset.size != descriptor.archive.size
        {
            return Err(UpdateError::Integrity);
        }
    }

    let selected = manifest
        .targets
        .iter()
        .find(|descriptor| descriptor.target == target)
        .ok_or(UpdateError::Integrity)?;
    let selected_asset = assets
        .get(&selected.archive.name)
        .ok_or(UpdateError::Integrity)?;

    Ok(VerifiedRelease {
        source_commit: manifest.source_commit,
        tag_ref_digest: manifest.tag_ref_digest,
        artifact: ArtifactReport {
            target: selected.target.clone(),
            name: selected.archive.name.clone(),
            url: selected_asset.browser_download_url.clone(),
            size: selected.archive.size,
            sha256: selected.archive.sha256.clone(),
        },
    })
}

fn expected_asset_names(version: &Version) -> BTreeSet<String> {
    let mut names = BTreeSet::from([MANIFEST_NAME.to_owned(), CHECKSUM_NAME.to_owned()]);
    for target in SUPPORTED_TARGETS {
        names.insert(archive_name(version, target));
    }
    names
}

fn archive_name(version: &Version, target: &str) -> String {
    let extension = if target == "x86_64-pc-windows-msvc" {
        ".zip"
    } else {
        ".tar.gz"
    };
    format!("calcifer-v{version}-{target}{extension}")
}

fn validate_api_asset(asset: &ReleaseAsset, release: &SelectedRelease) -> Result<(), UpdateError> {
    let expected_api_url = format!(
        "https://api.github.com/repos/{REPOSITORY}/releases/assets/{}",
        asset.id
    );
    let expected_download_url = format!(
        "https://github.com/{REPOSITORY}/releases/download/{}/{}",
        release.tag_name, asset.name
    );
    if asset.id == 0
        || asset.state != "uploaded"
        || !asset.name.is_ascii()
        || asset.url != expected_api_url
        || asset.browser_download_url != expected_download_url
        || asset_digest(asset).is_err()
    {
        return Err(UpdateError::Schema);
    }
    let size_limit = match asset.name.as_str() {
        MANIFEST_NAME => MAX_MANIFEST_BYTES as u64,
        CHECKSUM_NAME => MAX_CHECKSUM_BYTES as u64,
        _ => MAX_ARCHIVE_BYTES,
    };
    if asset.size == 0 || asset.size > size_limit {
        return Err(UpdateError::Schema);
    }
    Ok(())
}

fn asset_digest(asset: &ReleaseAsset) -> Result<String, UpdateError> {
    let digest = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .ok_or(UpdateError::Schema)?;
    if !is_lower_hex(digest, 64) {
        return Err(UpdateError::Schema);
    }
    Ok(digest.to_owned())
}

fn download_asset(
    transport: &impl Transport,
    asset: &ReleaseAsset,
    limit: usize,
) -> Result<Vec<u8>, UpdateError> {
    let bytes = fetch(transport, HttpRequest::asset(asset.url.clone()), limit)?;
    if bytes.len() as u64 != asset.size || sha256_hex(&bytes) != asset_digest(asset)? {
        return Err(UpdateError::Integrity);
    }
    Ok(bytes)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    attestations: ManifestAttestations,
    product: String,
    release_channel: String,
    repository: String,
    schema: String,
    source_commit: String,
    tag: String,
    tag_ref_digest: String,
    targets: Vec<TargetDescriptor>,
    version: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestAttestations {
    artifact: ArtifactAttestation,
    immutable_release: ImmutableReleaseAttestation,
    signer_workflow: SignerWorkflow,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactAttestation {
    job: String,
    kind: String,
    subjects: String,
    workflow: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImmutableReleaseAttestation {
    kind: String,
    required: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignerWorkflow {
    repository: String,
    workflow: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetDescriptor {
    architecture: String,
    archive: ArchiveDescriptor,
    binary: BinaryDescriptor,
    libc: Option<String>,
    os: String,
    runtime_requirements: Vec<RuntimeRequirement>,
    target: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveDescriptor {
    format: String,
    name: String,
    sha256: String,
    size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BinaryDescriptor {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRequirement {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum_version: Option<String>,
    name: String,
}

fn parse_manifest(bytes: &[u8]) -> Result<ReleaseManifest, UpdateError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES || !bytes.ends_with(b"\n") {
        return Err(UpdateError::Schema);
    }
    let without_newline = &bytes[..bytes.len() - 1];
    if without_newline.contains(&b'\n') || without_newline.contains(&b'\r') {
        return Err(UpdateError::Schema);
    }
    let manifest: ReleaseManifest =
        serde_json::from_slice(without_newline).map_err(|_| UpdateError::Schema)?;
    let value = serde_json::to_value(&manifest).map_err(|_| UpdateError::Schema)?;
    let mut canonical = serde_json::to_vec(&value).map_err(|_| UpdateError::Schema)?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(UpdateError::Schema);
    }
    Ok(manifest)
}

fn validate_manifest(
    manifest: &ReleaseManifest,
    release: &SelectedRelease,
    channel: Channel,
) -> Result<(), UpdateError> {
    let version = parse_version(&manifest.version)?;
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.product != "calcifer"
        || manifest.repository != REPOSITORY
        || manifest.tag != release.tag_name
        || manifest.tag != format!("v{version}")
        || version != release.version
        || manifest.release_channel != channel.label()
        || !is_lower_hex(&manifest.source_commit, 40)
        || !is_lower_hex(&manifest.tag_ref_digest, 40)
        || manifest.attestations.artifact.kind != "github_artifact_attestation"
        || manifest.attestations.artifact.job != "publish"
        || manifest.attestations.artifact.subjects != "release_assets"
        || manifest.attestations.artifact.workflow != RELEASE_WORKFLOW
        || manifest.attestations.immutable_release.kind != "github_release_attestation"
        || !manifest.attestations.immutable_release.required
        || manifest.attestations.signer_workflow.repository != REPOSITORY
        || manifest.attestations.signer_workflow.workflow != RELEASE_WORKFLOW
        || manifest.targets.len() != SUPPORTED_TARGETS.len()
    {
        return Err(UpdateError::Schema);
    }

    for (descriptor, expected_target) in manifest.targets.iter().zip(SUPPORTED_TARGETS) {
        validate_target_descriptor(descriptor, &version, expected_target)?;
    }
    Ok(())
}

fn validate_target_descriptor(
    descriptor: &TargetDescriptor,
    version: &Version,
    expected_target: &str,
) -> Result<(), UpdateError> {
    let (architecture, os, libc, format, binary_name, requirements) =
        expected_target_metadata(expected_target);
    let prefix = format!("calcifer-v{version}-{expected_target}");
    if descriptor.target != expected_target
        || descriptor.architecture != architecture
        || descriptor.os != os
        || descriptor.libc.as_deref() != libc
        || descriptor.archive.name != archive_name(version, expected_target)
        || descriptor.archive.format != format
        || descriptor.archive.size == 0
        || descriptor.archive.size > MAX_ARCHIVE_BYTES
        || !is_lower_hex(&descriptor.archive.sha256, 64)
        || descriptor.binary.path != format!("{prefix}/{binary_name}")
        || !is_lower_hex(&descriptor.binary.sha256, 64)
        || descriptor.runtime_requirements != requirements
    {
        return Err(UpdateError::Schema);
    }
    Ok(())
}

impl PartialEq<RuntimeRequirement> for RuntimeRequirement {
    fn eq(&self, other: &RuntimeRequirement) -> bool {
        self.kind == other.kind
            && self.minimum_version == other.minimum_version
            && self.name == other.name
    }
}

fn expected_target_metadata(
    target: &str,
) -> (
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
    &'static str,
    Vec<RuntimeRequirement>,
) {
    match target {
        "aarch64-apple-darwin" => (
            "aarch64",
            "macos",
            None,
            "tar.gz",
            "calcifer",
            vec![os_requirement("macos")],
        ),
        "aarch64-unknown-linux-gnu" => (
            "aarch64",
            "linux",
            Some("glibc"),
            "tar.gz",
            "calcifer",
            vec![os_requirement("linux"), libc_requirement()],
        ),
        "x86_64-apple-darwin" => (
            "x86_64",
            "macos",
            None,
            "tar.gz",
            "calcifer",
            vec![os_requirement("macos")],
        ),
        "x86_64-pc-windows-msvc" => (
            "x86_64",
            "windows",
            None,
            "zip",
            "calcifer.exe",
            vec![os_requirement("windows"), abi_requirement()],
        ),
        "x86_64-unknown-linux-gnu" => (
            "x86_64",
            "linux",
            Some("glibc"),
            "tar.gz",
            "calcifer",
            vec![os_requirement("linux"), libc_requirement()],
        ),
        _ => ("", "", None, "", "", Vec::new()),
    }
}

fn os_requirement(name: &str) -> RuntimeRequirement {
    RuntimeRequirement {
        kind: "operating_system".to_owned(),
        minimum_version: None,
        name: name.to_owned(),
    }
}

fn libc_requirement() -> RuntimeRequirement {
    RuntimeRequirement {
        kind: "libc".to_owned(),
        minimum_version: Some("2.35".to_owned()),
        name: "glibc".to_owned(),
    }
}

fn abi_requirement() -> RuntimeRequirement {
    RuntimeRequirement {
        kind: "abi".to_owned(),
        minimum_version: None,
        name: "msvc".to_owned(),
    }
}

fn parse_checksums(
    bytes: &[u8],
    expected_names: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, UpdateError> {
    if bytes.is_empty()
        || bytes.len() > MAX_CHECKSUM_BYTES
        || bytes.contains(&b'\r')
        || !bytes.is_ascii()
    {
        return Err(UpdateError::Schema);
    }
    let content = bytes.strip_suffix(b"\n").ok_or(UpdateError::Schema)?;
    if content.is_empty() || content.ends_with(b"\n") {
        return Err(UpdateError::Schema);
    }
    let text = std::str::from_utf8(content).map_err(|_| UpdateError::Schema)?;
    let mut checksums = BTreeMap::new();
    let mut observed_order = Vec::new();
    for line in text.split('\n') {
        if line.len() < 67 || &line[64..66] != "  " {
            return Err(UpdateError::Schema);
        }
        let digest = &line[..64];
        let name = &line[66..];
        if !is_lower_hex(digest, 64)
            || name.is_empty()
            || !name.is_ascii()
            || checksums
                .insert(name.to_owned(), digest.to_owned())
                .is_some()
        {
            return Err(UpdateError::Schema);
        }
        observed_order.push(name.to_owned());
    }
    let expected_order = expected_names.iter().cloned().collect::<Vec<_>>();
    if observed_order != expected_order
        || checksums.keys().cloned().collect::<BTreeSet<_>>() != *expected_names
    {
        return Err(UpdateError::Integrity);
    }
    Ok(checksums)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Clone, Debug)]
struct HttpRequest {
    url: String,
    accept: &'static str,
}

impl HttpRequest {
    fn api(url: String) -> Self {
        Self {
            url,
            accept: API_ACCEPT,
        }
    }

    fn asset(url: String) -> Self {
        Self {
            url,
            accept: ASSET_ACCEPT,
        }
    }

    const fn headers(&self) -> [(&'static str, &'static str); 3] {
        [
            ("Accept", self.accept),
            ("User-Agent", USER_AGENT),
            ("X-GitHub-Api-Version", API_VERSION),
        ]
    }
}

#[derive(Clone, Debug, Default)]
struct HttpHeaders {
    content_encoding: Option<String>,
    content_length: Option<String>,
    location: Option<String>,
    rate_limit_remaining: Option<String>,
}

#[derive(Clone, Debug)]
struct HttpResponse {
    status: u16,
    headers: HttpHeaders,
    body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportFailure {
    Network,
    ResponseTooLarge,
}

trait Transport {
    fn get(
        &self,
        request: &HttpRequest,
        max_body_bytes: usize,
    ) -> Result<HttpResponse, TransportFailure>;
}

struct HttpTransport {
    agent: ureq::Agent,
}

impl HttpTransport {
    fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .max_response_header_size(16 * 1024)
            .max_idle_connections(2)
            .max_idle_connections_per_host(1)
            .user_agent("")
            .accept("")
            .accept_encoding("")
            .http_status_as_error(false)
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl Transport for HttpTransport {
    fn get(
        &self,
        request: &HttpRequest,
        max_body_bytes: usize,
    ) -> Result<HttpResponse, TransportFailure> {
        let mut builder = self.agent.get(&request.url);
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        let mut response = builder.call().map_err(|_| TransportFailure::Network)?;
        let headers = HttpHeaders {
            content_encoding: response
                .headers()
                .get("content-encoding")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            content_length: response
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            location: response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            rate_limit_remaining: response
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        };
        if headers
            .content_length
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > max_body_bytes as u64)
        {
            return Err(TransportFailure::ResponseTooLarge);
        }
        let read_limit = max_body_bytes
            .checked_add(1)
            .ok_or(TransportFailure::ResponseTooLarge)?;
        let mut body = Vec::with_capacity(max_body_bytes.min(16 * 1024));
        response
            .body_mut()
            .as_reader()
            .take(read_limit as u64)
            .read_to_end(&mut body)
            .map_err(|_| TransportFailure::Network)?;
        if body.len() > max_body_bytes {
            return Err(TransportFailure::ResponseTooLarge);
        }
        Ok(HttpResponse {
            status: response.status().as_u16(),
            headers,
            body,
        })
    }
}

fn fetch(
    transport: &impl Transport,
    request: HttpRequest,
    max_body_bytes: usize,
) -> Result<Vec<u8>, UpdateError> {
    validate_https_url(&request.url)?;
    let mut current = request;
    for redirect_count in 0..=MAX_REDIRECTS {
        let response =
            transport
                .get(&current, max_body_bytes)
                .map_err(|failure| match failure {
                    TransportFailure::Network => UpdateError::Network,
                    TransportFailure::ResponseTooLarge => UpdateError::ResponseTooLarge,
                })?;
        if response.body.len() > max_body_bytes {
            return Err(UpdateError::ResponseTooLarge);
        }
        if response
            .headers
            .content_encoding
            .as_deref()
            .is_some_and(|encoding| !encoding.eq_ignore_ascii_case("identity"))
        {
            return Err(UpdateError::Schema);
        }
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            if redirect_count == MAX_REDIRECTS {
                return Err(UpdateError::RedirectRejected);
            }
            let location = response
                .headers
                .location
                .as_deref()
                .ok_or(UpdateError::RedirectRejected)?;
            validate_https_url(location)?;
            current.url = location.to_owned();
            continue;
        }
        if response.status == 429
            || (response.status == 403
                && response.headers.rate_limit_remaining.as_deref() == Some("0"))
        {
            return Err(UpdateError::RateLimited);
        }
        if response.status != 200 {
            return Err(UpdateError::Network);
        }
        return Ok(response.body);
    }
    Err(UpdateError::RedirectRejected)
}

fn validate_https_url(value: &str) -> Result<(), UpdateError> {
    if value.len() > MAX_REDIRECT_LOCATION_BYTES || !value.is_ascii() {
        return Err(UpdateError::RedirectRejected);
    }
    let uri: Uri = value.parse().map_err(|_| UpdateError::RedirectRejected)?;
    if uri.scheme_str() != Some("https")
        || uri.path().is_empty()
        || !matches!(
            uri.authority().map(|authority| authority.as_str()),
            Some(
                "api.github.com"
                    | "github.com"
                    | "release-assets.githubusercontent.com"
                    | "objects.githubusercontent.com"
            )
        )
    {
        return Err(UpdateError::RedirectRejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use serde_json::json;

    use super::*;

    struct FakeTransport {
        responses: RefCell<BTreeMap<String, VecDeque<Result<HttpResponse, TransportFailure>>>>,
        requests: RefCell<Vec<HttpRequest>>,
    }

    impl FakeTransport {
        fn new(entries: Vec<(String, Result<HttpResponse, TransportFailure>)>) -> Self {
            let mut responses: BTreeMap<String, VecDeque<Result<HttpResponse, TransportFailure>>> =
                BTreeMap::new();
            for (url, response) in entries {
                responses.entry(url).or_default().push_back(response);
            }
            Self {
                responses: RefCell::new(responses),
                requests: RefCell::new(Vec::new()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.borrow().len()
        }
    }

    impl Transport for FakeTransport {
        fn get(
            &self,
            request: &HttpRequest,
            _max_body_bytes: usize,
        ) -> Result<HttpResponse, TransportFailure> {
            self.requests.borrow_mut().push(request.clone());
            self.responses
                .borrow_mut()
                .get_mut(&request.url)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Err(TransportFailure::Network))
        }
    }

    struct Fixture {
        list_url: String,
        manifest_url: String,
        checksum_url: String,
        release_body: Vec<u8>,
        manifest: Vec<u8>,
        checksums: Vec<u8>,
    }

    impl Fixture {
        fn transport(&self) -> FakeTransport {
            FakeTransport::new(vec![
                (
                    self.list_url.clone(),
                    Ok(ok_response(self.release_body.clone())),
                ),
                (
                    self.manifest_url.clone(),
                    Ok(ok_response(self.manifest.clone())),
                ),
                (
                    self.checksum_url.clone(),
                    Ok(ok_response(self.checksums.clone())),
                ),
            ])
        }
    }

    fn fixture(version: &str, immutable: bool) -> Fixture {
        let parsed = parse_version(version).unwrap_or_else(|_| panic!("invalid fixture version"));
        let channel = if parsed.pre.is_empty() {
            "stable"
        } else {
            "preview"
        };
        let targets = SUPPORTED_TARGETS
            .iter()
            .enumerate()
            .map(|(index, target)| {
                let (architecture, os, libc, format, binary, requirements) =
                    expected_target_metadata(target);
                json!({
                    "architecture": architecture,
                    "archive": {
                        "format": format,
                        "name": archive_name(&parsed, target),
                        "sha256": format!("{:064x}", index + 1),
                        "size": 1000 + index,
                    },
                    "binary": {
                        "path": format!("calcifer-v{parsed}-{target}/{binary}"),
                        "sha256": format!("{:064x}", index + 11),
                    },
                    "libc": libc,
                    "os": os,
                    "runtime_requirements": requirements,
                    "target": target,
                })
            })
            .collect::<Vec<_>>();
        let manifest_document = json!({
            "attestations": {
                "artifact": {
                    "job": "publish",
                    "kind": "github_artifact_attestation",
                    "subjects": "release_assets",
                    "workflow": RELEASE_WORKFLOW,
                },
                "immutable_release": {
                    "kind": "github_release_attestation",
                    "required": true,
                },
                "signer_workflow": {
                    "repository": REPOSITORY,
                    "workflow": RELEASE_WORKFLOW,
                },
            },
            "product": "calcifer",
            "release_channel": channel,
            "repository": REPOSITORY,
            "schema": MANIFEST_SCHEMA,
            "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tag": format!("v{parsed}"),
            "tag_ref_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "targets": targets,
            "version": parsed.to_string(),
        });
        let mut manifest = serde_json::to_vec(&manifest_document)
            .unwrap_or_else(|_| panic!("fixture manifest serialization failed"));
        manifest.push(b'\n');
        let mut checksum_entries = BTreeMap::new();
        checksum_entries.insert(MANIFEST_NAME.to_owned(), sha256_hex(&manifest));
        for (index, target) in SUPPORTED_TARGETS.iter().enumerate() {
            checksum_entries.insert(archive_name(&parsed, target), format!("{:064x}", index + 1));
        }
        let checksums = checksum_entries
            .iter()
            .map(|(name, digest)| format!("{digest}  {name}\n"))
            .collect::<String>()
            .into_bytes();

        let manifest_url = format!("https://api.github.com/repos/{REPOSITORY}/releases/assets/1");
        let checksum_url = format!("https://api.github.com/repos/{REPOSITORY}/releases/assets/2");
        let mut assets = vec![api_asset(1, &parsed, MANIFEST_NAME, &manifest, None)];
        assets.push(api_asset(2, &parsed, CHECKSUM_NAME, &checksums, None));
        for (index, target) in SUPPORTED_TARGETS.iter().enumerate() {
            assets.push(api_asset(
                10 + index as u64,
                &parsed,
                &archive_name(&parsed, target),
                &[],
                Some((1000 + index as u64, format!("{:064x}", index + 1))),
            ));
        }
        let release = json!({
            "id": 42,
            "tag_name": format!("v{parsed}"),
            "html_url": format!("https://github.com/{REPOSITORY}/releases/tag/v{parsed}"),
            "draft": false,
            "prerelease": !parsed.pre.is_empty(),
            "immutable": immutable,
            "published_at": "2026-07-15T00:00:00Z",
            "assets": assets,
        });
        Fixture {
            list_url: releases_url(1),
            manifest_url,
            checksum_url,
            release_body: serde_json::to_vec(&vec![release])
                .unwrap_or_else(|_| panic!("fixture release serialization failed")),
            manifest,
            checksums,
        }
    }

    fn api_asset(
        id: u64,
        version: &Version,
        name: &str,
        bytes: &[u8],
        metadata: Option<(u64, String)>,
    ) -> serde_json::Value {
        let (size, digest) = metadata.unwrap_or_else(|| (bytes.len() as u64, sha256_hex(bytes)));
        json!({
            "id": id,
            "url": format!("https://api.github.com/repos/{REPOSITORY}/releases/assets/{id}"),
            "browser_download_url": format!("https://github.com/{REPOSITORY}/releases/download/v{version}/{name}"),
            "name": name,
            "state": "uploaded",
            "size": size,
            "digest": format!("sha256:{digest}"),
        })
    }

    fn releases_url(page: u8) -> String {
        format!(
            "https://api.github.com/repos/{REPOSITORY}/releases?per_page={RELEASES_PER_PAGE}&page={page}"
        )
    }

    fn ok_response(body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: HttpHeaders::default(),
            body,
        }
    }

    fn error_code(result: Result<UpdateReport, UpdateError>) -> &'static str {
        match result {
            Err(error) => error.code(),
            Ok(_) => "unexpected_success",
        }
    }

    fn report_json(report: &UpdateReport) -> serde_json::Value {
        let encoded = report
            .to_json()
            .unwrap_or_else(|_| panic!("report serialization failed"));
        serde_json::from_str(&encoded).unwrap_or_else(|_| panic!("report JSON is invalid"))
    }

    fn replace_asset_bytes(release_body: &mut [serde_json::Value], name: &str, bytes: &[u8]) {
        let Some(release) = release_body.first_mut() else {
            panic!("fixture release is absent");
        };
        let Some(assets) = release["assets"].as_array_mut() else {
            panic!("fixture assets are absent");
        };
        let Some(asset) = assets.iter_mut().find(|asset| asset["name"] == name) else {
            panic!("fixture asset is absent");
        };
        asset["size"] = json!(bytes.len());
        asset["digest"] = json!(format!("sha256:{}", sha256_hex(bytes)));
    }

    fn transport_with_manifest(
        fixture: &Fixture,
        manifest_document: &serde_json::Value,
    ) -> FakeTransport {
        let mut manifest = serde_json::to_vec(manifest_document)
            .unwrap_or_else(|_| panic!("fixture manifest serialization failed"));
        manifest.push(b'\n');
        let manifest_digest = sha256_hex(&manifest);
        let checksums = std::str::from_utf8(&fixture.checksums)
            .unwrap_or_else(|_| panic!("fixture checksums are not canonical UTF-8"))
            .lines()
            .map(|line| {
                if line.ends_with(MANIFEST_NAME) {
                    format!("{manifest_digest}  {MANIFEST_NAME}\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect::<String>()
            .into_bytes();
        let mut releases: Vec<serde_json::Value> = serde_json::from_slice(&fixture.release_body)
            .unwrap_or_else(|_| panic!("fixture release JSON is invalid"));
        replace_asset_bytes(&mut releases, MANIFEST_NAME, &manifest);
        replace_asset_bytes(&mut releases, CHECKSUM_NAME, &checksums);
        let release_body = serde_json::to_vec(&releases)
            .unwrap_or_else(|_| panic!("fixture release serialization failed"));

        FakeTransport::new(vec![
            (fixture.list_url.clone(), Ok(ok_response(release_body))),
            (fixture.manifest_url.clone(), Ok(ok_response(manifest))),
            (fixture.checksum_url.clone(), Ok(ok_response(checksums))),
        ])
    }

    #[test]
    fn valid_preview_release_reports_verified_metadata_but_not_archive_bytes() {
        let fixture = fixture("0.2.0-alpha.1", true);
        let transport = fixture.transport();
        let result = check_with(
            &transport,
            Channel::Preview,
            "0.1.0-alpha.3",
            "aarch64-apple-darwin",
        );
        let Ok(report) = result else {
            panic!("valid release must pass: {result:?}");
        };
        let document = report_json(&report);

        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["command"], "update");
        assert_eq!(document["action"], "check");
        assert_eq!(document["status"], "update_available");
        assert_eq!(document["channel"], "preview");
        assert_eq!(document["target"], "aarch64-apple-darwin");
        assert_eq!(document["release"]["immutable"], true);
        assert_eq!(document["verification"]["manifest_bytes"], "verified");
        assert_eq!(document["verification"]["checksums_bytes"], "verified");
        assert_eq!(
            document["verification"]["selected_archive_bytes"],
            "not_downloaded"
        );
        assert_eq!(
            document["verification"]["published_attestations"]["artifact"]["publication"],
            "declared_by_manifest_not_queried"
        );
        assert_eq!(
            document["verification"]["published_attestations"]["artifact"]["locally_verified"],
            false
        );
        let human = report.to_human();
        assert!(human.contains("Published attestations:"));
        assert!(human.contains("was not locally verified"));
        assert!(human.contains("selected archive not downloaded"));
        assert_eq!(transport.request_count(), 3);
    }

    #[test]
    fn unsupported_compile_target_succeeds_without_network_or_abi_fallback() {
        let transport = FakeTransport::new(Vec::new());
        let result = check_with(
            &transport,
            Channel::Stable,
            "1.0.0",
            "aarch64-pc-windows-msvc",
        );
        let Ok(report) = result else {
            panic!("unsupported target is a successful result");
        };
        let document = report_json(&report);
        assert_eq!(document["status"], "target_unsupported");
        assert_eq!(document["release"], serde_json::Value::Null);
        assert_eq!(document["next_action"]["code"], "build_from_source");
        assert_eq!(transport.request_count(), 0);
    }

    #[test]
    fn absent_channel_succeeds_without_fabricating_a_release() {
        let transport =
            FakeTransport::new(vec![(releases_url(1), Ok(ok_response(b"[]".to_vec())))]);
        let result = check_with(
            &transport,
            Channel::Stable,
            "1.0.0",
            "x86_64-unknown-linux-gnu",
        );
        let Ok(report) = result else {
            panic!("empty channel is a successful result");
        };
        let document = report_json(&report);
        assert_eq!(document["status"], "no_release_in_channel");
        assert_eq!(document["release"], serde_json::Value::Null);
        assert_eq!(document["next_action"]["code"], "retry_later");
    }

    #[test]
    fn stable_and_preview_channels_never_cross_select() {
        let stable = fixture("1.0.0", true);
        let preview = fixture("2.0.0-alpha.1", true);
        let stable_release: serde_json::Value =
            serde_json::from_slice::<Vec<_>>(&stable.release_body)
                .unwrap_or_else(|_| panic!("stable fixture is invalid"))
                .pop()
                .unwrap_or_else(|| panic!("stable fixture is empty"));
        let preview_release: serde_json::Value =
            serde_json::from_slice::<Vec<_>>(&preview.release_body)
                .unwrap_or_else(|_| panic!("preview fixture is invalid"))
                .pop()
                .unwrap_or_else(|| panic!("preview fixture is empty"));
        let combined = serde_json::to_vec(&vec![preview_release, stable_release])
            .unwrap_or_else(|_| panic!("combined fixture serialization failed"));

        let stable_transport = FakeTransport::new(vec![
            (stable.list_url, Ok(ok_response(combined.clone()))),
            (stable.manifest_url, Ok(ok_response(stable.manifest))),
            (stable.checksum_url, Ok(ok_response(stable.checksums))),
        ]);
        let stable_result = check_with(
            &stable_transport,
            Channel::Stable,
            "0.9.0",
            "x86_64-unknown-linux-gnu",
        );
        let Ok(stable_report) = stable_result else {
            panic!("strict stable selection failed: {stable_result:?}");
        };
        assert_eq!(report_json(&stable_report)["release"]["version"], "1.0.0");

        let preview_transport = FakeTransport::new(vec![
            (preview.list_url, Ok(ok_response(combined))),
            (preview.manifest_url, Ok(ok_response(preview.manifest))),
            (preview.checksum_url, Ok(ok_response(preview.checksums))),
        ]);
        let preview_result = check_with(
            &preview_transport,
            Channel::Preview,
            "1.0.0-alpha.1",
            "x86_64-unknown-linux-gnu",
        );
        let Ok(preview_report) = preview_result else {
            panic!("strict preview selection failed: {preview_result:?}");
        };
        assert_eq!(
            report_json(&preview_report)["release"]["version"],
            "2.0.0-alpha.1"
        );
    }

    #[test]
    fn current_version_channel_is_strict() {
        assert_eq!(channel_for_version("1.0.0"), Ok(Channel::Stable));
        assert_eq!(channel_for_version("1.0.0-alpha.1"), Ok(Channel::Preview));
        assert_eq!(
            error_code(
                channel_for_version("1.0.0+build")
                    .map(|_| { UpdateReport::no_release(Channel::Stable, "1.0.0", "target") })
            ),
            "update_schema_error"
        );
    }

    #[test]
    fn malformed_and_partial_release_documents_fail_as_schema_errors() {
        for body in [b"not-json".to_vec(), b"[{\"id\":1}]".to_vec()] {
            let transport = FakeTransport::new(vec![(releases_url(1), Ok(ok_response(body)))]);
            assert_eq!(
                error_code(check_with(
                    &transport,
                    Channel::Preview,
                    "0.1.0-alpha.3",
                    "x86_64-apple-darwin",
                )),
                "update_schema_error"
            );
        }
    }

    #[test]
    fn oversized_response_is_rejected_even_if_transport_returns_it() {
        let transport = FakeTransport::new(vec![(
            releases_url(1),
            Ok(ok_response(vec![b' '; MAX_RELEASE_PAGE_BYTES + 1])),
        )]);
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Stable,
                "1.0.0",
                "x86_64-pc-windows-msvc",
            )),
            "update_response_too_large"
        );
    }

    #[test]
    fn anonymous_rate_limit_is_actionable_and_nonzero() {
        let transport = FakeTransport::new(vec![(
            releases_url(1),
            Ok(HttpResponse {
                status: 403,
                headers: HttpHeaders {
                    rate_limit_remaining: Some("0".to_owned()),
                    ..HttpHeaders::default()
                },
                body: Vec::new(),
            }),
        )]);
        let result = check_with(&transport, Channel::Stable, "1.0.0", "x86_64-apple-darwin");
        assert_eq!(error_code(result), "update_rate_limited");
    }

    #[test]
    fn redirect_to_non_allowlisted_host_is_rejected() {
        let transport = FakeTransport::new(vec![(
            releases_url(1),
            Ok(HttpResponse {
                status: 302,
                headers: HttpHeaders {
                    location: Some("https://example.invalid/releases".to_owned()),
                    ..HttpHeaders::default()
                },
                body: Vec::new(),
            }),
        )]);
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Stable,
                "1.0.0",
                "x86_64-apple-darwin",
            )),
            "update_redirect_rejected"
        );
    }

    #[test]
    fn allowlisted_asset_redirect_preserves_bounded_verification() {
        let fixture = fixture("0.2.0-alpha.1", true);
        let redirected = "https://release-assets.githubusercontent.com/signed/manifest";
        let transport = FakeTransport::new(vec![
            (
                fixture.list_url.clone(),
                Ok(ok_response(fixture.release_body.clone())),
            ),
            (
                fixture.manifest_url.clone(),
                Ok(HttpResponse {
                    status: 302,
                    headers: HttpHeaders {
                        location: Some(redirected.to_owned()),
                        ..HttpHeaders::default()
                    },
                    body: Vec::new(),
                }),
            ),
            (redirected.to_owned(), Ok(ok_response(fixture.manifest))),
            (fixture.checksum_url, Ok(ok_response(fixture.checksums))),
        ]);
        let result = check_with(
            &transport,
            Channel::Preview,
            "0.1.0-alpha.3",
            "x86_64-apple-darwin",
        );
        assert!(result.is_ok(), "allowlisted redirect failed: {result:?}");
        assert_eq!(transport.request_count(), 4);
    }

    #[test]
    fn mutable_selected_release_fails_before_asset_download() {
        let fixture = fixture("0.2.0-alpha.1", false);
        let transport = fixture.transport();
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Preview,
                "0.1.0-alpha.3",
                "x86_64-apple-darwin",
            )),
            "update_integrity_error"
        );
        assert_eq!(transport.request_count(), 1);
    }

    #[test]
    fn local_manifest_digest_mismatch_fails_integrity() {
        let fixture = fixture("0.2.0-alpha.1", true);
        let mut changed_manifest = fixture.manifest.clone();
        changed_manifest[0] ^= 1;
        let transport = FakeTransport::new(vec![
            (fixture.list_url, Ok(ok_response(fixture.release_body))),
            (fixture.manifest_url, Ok(ok_response(changed_manifest))),
        ]);
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Preview,
                "0.1.0-alpha.3",
                "x86_64-apple-darwin",
            )),
            "update_integrity_error"
        );
    }

    #[test]
    fn partial_or_extra_asset_set_fails_closed() {
        let fixture = fixture("0.2.0-alpha.1", true);
        let mut releases: Vec<serde_json::Value> = serde_json::from_slice(&fixture.release_body)
            .unwrap_or_else(|_| panic!("fixture release JSON is invalid"));
        let Some(release) = releases.first_mut() else {
            panic!("fixture release is absent");
        };
        let Some(assets) = release["assets"].as_array_mut() else {
            panic!("fixture assets are absent");
        };
        assets.pop();
        assets.push(json!({
            "id": 999,
            "url": format!("https://api.github.com/repos/{REPOSITORY}/releases/assets/999"),
            "browser_download_url": format!("https://github.com/{REPOSITORY}/releases/download/v0.2.0-alpha.1/unexpected"),
            "name": "unexpected",
            "state": "uploaded",
            "size": 1,
            "digest": format!("sha256:{}", "c".repeat(64)),
        }));
        let transport = FakeTransport::new(vec![(
            fixture.list_url,
            Ok(ok_response(serde_json::to_vec(&releases).unwrap_or_else(
                |_| panic!("fixture serialization failed"),
            ))),
        )]);
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Preview,
                "0.1.0-alpha.3",
                "x86_64-apple-darwin",
            )),
            "update_integrity_error"
        );
    }

    #[test]
    fn noncanonical_manifest_and_checksum_bytes_are_rejected() {
        let fixture = fixture("0.2.0-alpha.1", true);
        let pretty_manifest: serde_json::Value = serde_json::from_slice(&fixture.manifest)
            .unwrap_or_else(|_| panic!("fixture manifest is invalid"));
        let pretty_manifest = serde_json::to_vec_pretty(&pretty_manifest)
            .unwrap_or_else(|_| panic!("pretty serialization failed"));
        let transport = FakeTransport::new(vec![
            (
                fixture.list_url.clone(),
                Ok(ok_response(fixture.release_body.clone())),
            ),
            (
                fixture.manifest_url.clone(),
                Ok(ok_response(pretty_manifest)),
            ),
        ]);
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Preview,
                "0.1.0-alpha.3",
                "x86_64-apple-darwin",
            )),
            "update_integrity_error",
            "release-asset digest must fail before noncanonical bytes are parsed"
        );

        let transport = FakeTransport::new(vec![
            (fixture.list_url, Ok(ok_response(fixture.release_body))),
            (fixture.manifest_url, Ok(ok_response(fixture.manifest))),
            (
                fixture.checksum_url,
                Ok(ok_response(b"bad checksum\n".to_vec())),
            ),
        ]);
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Preview,
                "0.1.0-alpha.3",
                "x86_64-apple-darwin",
            )),
            "update_integrity_error"
        );
    }

    #[test]
    fn malformed_manifest_and_checksum_fail_after_matching_local_digests() {
        let fixture = fixture("0.2.0-alpha.1", true);
        let mut release: Vec<serde_json::Value> = serde_json::from_slice(&fixture.release_body)
            .unwrap_or_else(|_| panic!("fixture release JSON is invalid"));
        let mut manifest_value: serde_json::Value = serde_json::from_slice(&fixture.manifest)
            .unwrap_or_else(|_| panic!("fixture manifest is invalid"));
        manifest_value["unexpected"] = json!(true);
        let mut malformed_manifest = serde_json::to_vec(&manifest_value)
            .unwrap_or_else(|_| panic!("malformed manifest serialization failed"));
        malformed_manifest.push(b'\n');
        replace_asset_bytes(&mut release, MANIFEST_NAME, &malformed_manifest);
        let release_body = serde_json::to_vec(&release)
            .unwrap_or_else(|_| panic!("fixture release serialization failed"));
        let transport = FakeTransport::new(vec![
            (fixture.list_url.clone(), Ok(ok_response(release_body))),
            (
                fixture.manifest_url.clone(),
                Ok(ok_response(malformed_manifest)),
            ),
            (
                fixture.checksum_url.clone(),
                Ok(ok_response(fixture.checksums.clone())),
            ),
        ]);
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Preview,
                "0.1.0-alpha.3",
                "x86_64-apple-darwin",
            )),
            "update_schema_error"
        );

        let malformed_checksums = b"bad checksum\n".to_vec();
        let mut release: Vec<serde_json::Value> = serde_json::from_slice(&fixture.release_body)
            .unwrap_or_else(|_| panic!("fixture release JSON is invalid"));
        replace_asset_bytes(&mut release, CHECKSUM_NAME, &malformed_checksums);
        let release_body = serde_json::to_vec(&release)
            .unwrap_or_else(|_| panic!("fixture release serialization failed"));
        let transport = FakeTransport::new(vec![
            (fixture.list_url, Ok(ok_response(release_body))),
            (fixture.manifest_url, Ok(ok_response(fixture.manifest))),
            (fixture.checksum_url, Ok(ok_response(malformed_checksums))),
        ]);
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Preview,
                "0.1.0-alpha.3",
                "x86_64-apple-darwin",
            )),
            "update_schema_error"
        );
    }

    #[test]
    fn manifest_requires_explicit_null_libc_for_targets_without_libc() {
        let fixture = fixture("0.2.0-alpha.1", true);
        let mut manifest: serde_json::Value = serde_json::from_slice(&fixture.manifest)
            .unwrap_or_else(|_| panic!("fixture manifest is invalid"));
        manifest["targets"][0]
            .as_object_mut()
            .unwrap_or_else(|| panic!("fixture target is not an object"))
            .remove("libc");
        let transport = transport_with_manifest(&fixture, &manifest);

        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Preview,
                "0.1.0-alpha.3",
                "aarch64-apple-darwin",
            )),
            "update_schema_error"
        );
    }

    #[test]
    fn manifest_rejects_explicit_null_for_omitted_minimum_version() {
        let fixture = fixture("0.2.0-alpha.1", true);
        let mut manifest: serde_json::Value = serde_json::from_slice(&fixture.manifest)
            .unwrap_or_else(|_| panic!("fixture manifest is invalid"));
        manifest["targets"][0]["runtime_requirements"][0]["minimum_version"] =
            serde_json::Value::Null;
        let transport = transport_with_manifest(&fixture, &manifest);

        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Preview,
                "0.1.0-alpha.3",
                "aarch64-apple-darwin",
            )),
            "update_schema_error"
        );
    }

    #[test]
    fn pagination_is_bounded_and_incomplete_inventory_never_selects() {
        let mut entries = Vec::new();
        for page in 1..=MAX_RELEASE_PAGES {
            let releases = (0..RELEASES_PER_PAGE)
                .map(|index| {
                    let patch = usize::from(page) * RELEASES_PER_PAGE + index;
                    json!({
                        "id": patch + 1,
                        "tag_name": format!("v1.0.{patch}"),
                        "html_url": format!("https://github.com/{REPOSITORY}/releases/tag/v1.0.{patch}"),
                        "draft": false,
                        "prerelease": false,
                        "immutable": true,
                        "published_at": "2026-07-15T00:00:00Z",
                        "assets": [],
                    })
                })
                .collect::<Vec<_>>();
            entries.push((
                releases_url(page),
                Ok(ok_response(
                    serde_json::to_vec(&releases)
                        .unwrap_or_else(|_| panic!("pagination fixture failed")),
                )),
            ));
        }
        let transport = FakeTransport::new(entries);
        assert_eq!(
            error_code(check_with(
                &transport,
                Channel::Stable,
                "1.0.0",
                "x86_64-apple-darwin",
            )),
            "update_pagination_limit"
        );
        assert_eq!(transport.request_count(), usize::from(MAX_RELEASE_PAGES));
    }

    #[test]
    fn encoded_or_failed_transport_responses_fail_nonzero() {
        let encoded = FakeTransport::new(vec![(
            releases_url(1),
            Ok(HttpResponse {
                status: 200,
                headers: HttpHeaders {
                    content_encoding: Some("gzip".to_owned()),
                    ..HttpHeaders::default()
                },
                body: b"[]".to_vec(),
            }),
        )]);
        assert_eq!(
            error_code(check_with(
                &encoded,
                Channel::Stable,
                "1.0.0",
                "x86_64-apple-darwin",
            )),
            "update_schema_error"
        );

        let failed = FakeTransport::new(vec![(releases_url(1), Err(TransportFailure::Network))]);
        assert_eq!(
            error_code(check_with(
                &failed,
                Channel::Stable,
                "1.0.0",
                "x86_64-apple-darwin",
            )),
            "update_network_error"
        );
    }

    #[test]
    fn checksum_parser_rejects_non_ascii_without_panicking() {
        let expected_names = BTreeSet::from([MANIFEST_NAME.to_owned()]);
        let malformed = format!("{}é  {MANIFEST_NAME}\n", "a".repeat(63));

        assert!(matches!(
            parse_checksums(malformed.as_bytes(), &expected_names),
            Err(UpdateError::Schema)
        ));
    }

    #[test]
    fn checksum_parser_rejects_more_than_one_trailing_newline() {
        let expected_names = BTreeSet::from([MANIFEST_NAME.to_owned()]);
        let malformed = format!("{}  {MANIFEST_NAME}\n\n", "a".repeat(64));

        assert!(matches!(
            parse_checksums(malformed.as_bytes(), &expected_names),
            Err(UpdateError::Schema)
        ));
    }

    #[test]
    fn requests_have_only_public_fixed_headers_and_ignore_secret_shaped_environment() {
        let fixture = fixture("0.2.0-alpha.1", true);
        let transport = fixture.transport();
        let _ = check_with(
            &transport,
            Channel::Preview,
            "0.1.0-alpha.3",
            "x86_64-apple-darwin",
        );
        let requests = transport.requests.borrow();
        assert!(!requests.is_empty());
        for request in requests.iter() {
            let headers = request.headers();
            assert_eq!(headers.len(), 3);
            assert!(headers.iter().any(|(name, _)| *name == "Accept"));
            assert!(headers.iter().all(|(name, _)| {
                !matches!(
                    name.to_ascii_lowercase().as_str(),
                    "authorization" | "cookie" | "proxy-authorization"
                )
            }));
        }
    }

    #[test]
    fn response_and_redirect_bounds_are_explicit() {
        let response_too_large = FakeTransport::new(vec![(
            releases_url(1),
            Err(TransportFailure::ResponseTooLarge),
        )]);
        assert_eq!(
            error_code(check_with(
                &response_too_large,
                Channel::Stable,
                "1.0.0",
                "x86_64-apple-darwin",
            )),
            "update_response_too_large"
        );

        let mut entries = Vec::new();
        let first = releases_url(1);
        let mut current = first.clone();
        for index in 0..=MAX_REDIRECTS {
            let next = format!("https://api.github.com/redirect/{index}");
            entries.push((
                current,
                Ok(HttpResponse {
                    status: 302,
                    headers: HttpHeaders {
                        location: Some(next.clone()),
                        ..HttpHeaders::default()
                    },
                    body: Vec::new(),
                }),
            ));
            current = next;
        }
        let redirect_loop = FakeTransport::new(entries);
        assert_eq!(
            error_code(check_with(
                &redirect_loop,
                Channel::Stable,
                "1.0.0",
                "x86_64-apple-darwin",
            )),
            "update_redirect_rejected"
        );
    }
}
