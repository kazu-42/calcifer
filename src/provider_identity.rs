use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::providers::codex::CodexIdentityAdapter;

pub(crate) const IDENTITY_KEY_FILE: &str = "identity.key";
pub(crate) const IDENTITY_MARKER_FILE: &str = ".calcifer-identity";

const IDENTITY_KEY_SCHEMA_VERSION: u8 = 1;
const IDENTITY_MARKER_SCHEMA_VERSION: u8 = 1;
const IDENTITY_KEY_BYTES: usize = 32;
const FINGERPRINT_BYTES: usize = 32;
const MAX_IDENTITY_KEY_BYTES: usize = 1024;
const MAX_IDENTITY_MARKER_BYTES: usize = 2048;
const MAX_CODEX_AUTH_BYTES: usize = 1024 * 1024;
const MAX_ACCOUNT_SCOPE_BYTES: usize = 1024;
const CODEX_PROVIDER: &str = "codex";
const CODEX_AUTH_KIND: &str = "chatgpt";
const FINGERPRINT_DOMAIN: &[u8] = b"calcifer-provider-identity-v1";

type HmacSha256 = Hmac<Sha256>;

/// A private equality token. It intentionally implements neither `Debug` nor
/// `Serialize`, preventing accidental propagation into diagnostics or DTOs.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ProviderIdentity {
    key_id: String,
    adapter_id: &'static str,
    auth_kind: &'static str,
    fingerprint: [u8; FINGERPRINT_BYTES],
}

impl ProviderIdentity {
    pub(crate) fn same_provider_identity(&self, other: &Self) -> bool {
        self == other
    }
}

pub(crate) struct IdentityKey {
    key_id: String,
    secret: [u8; IDENTITY_KEY_BYTES],
}

#[derive(Debug)]
pub(crate) enum IdentityError {
    Unverified,
    Unsupported,
    Invalid,
    Mismatch,
    KeyUnavailable,
    CommitUncertain,
    Io(io::Error),
}

impl IdentityError {
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Unverified => "provider_identity_unverified",
            Self::Unsupported => "provider_identity_unsupported",
            Self::Invalid => "provider_identity_invalid",
            Self::Mismatch => "provider_identity_mismatch",
            Self::KeyUnavailable => "identity_key_unavailable",
            Self::CommitUncertain => "identity_commit_uncertain",
            Self::Io(_) => "io_error",
        }
    }

    pub(crate) fn safe_message(&self) -> &'static str {
        match self {
            Self::Unverified => {
                "The profile has no verified provider identity. Run `calcifer auth verify codex@<alias>` before using it for automatic selection."
            }
            Self::Unsupported => {
                "The installed Codex version or authentication mode is not supported for provider identity verification."
            }
            Self::Invalid => {
                "The private provider identity state or managed Codex authentication state is invalid."
            }
            Self::Mismatch => {
                "The managed Codex authentication no longer matches this profile's verified provider identity. Explicit recovery is required."
            }
            Self::KeyUnavailable => {
                "Calcifer's private provider identity key is missing, unreadable, or does not match existing bindings. Explicit re-key recovery is required."
            }
            Self::CommitUncertain => {
                "The private provider identity update became visible but its durability could not be confirmed. Inspect the profile before retrying."
            }
            Self::Io(error) => {
                let _ = error.kind();
                "Calcifer could not access its private provider identity storage."
            }
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for IdentityError {}

impl From<io::Error> for IdentityError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) struct IdentityStore<'a> {
    root: &'a Path,
}

impl<'a> IdentityStore<'a> {
    pub(crate) const fn new(root: &'a Path) -> Self {
        Self { root }
    }

    pub(crate) fn marker_exists(&self, profile_directory: &Path) -> Result<bool, IdentityError> {
        ensure_identity_supported()?;
        verify_identity_directory(profile_directory)?;
        match fs::symlink_metadata(profile_directory.join(IDENTITY_MARKER_FILE)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(IdentityError::Io(error)),
        }
    }

    pub(crate) fn load_or_create_key(
        &self,
        existing_bindings: bool,
    ) -> Result<IdentityKey, IdentityError> {
        ensure_identity_supported()?;
        verify_identity_directory(self.root).map_err(|_| IdentityError::KeyUnavailable)?;
        let path = self.root.join(IDENTITY_KEY_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => read_identity_key(&path).map_err(normalize_key_error),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if existing_bindings {
                    return Err(IdentityError::KeyUnavailable);
                }
                self.create_key()
            }
            Err(_) => Err(IdentityError::KeyUnavailable),
        }
    }

    pub(crate) fn load_key(&self) -> Result<IdentityKey, IdentityError> {
        ensure_identity_supported()?;
        verify_identity_directory(self.root).map_err(|_| IdentityError::KeyUnavailable)?;
        let path = self.root.join(IDENTITY_KEY_FILE);
        read_identity_key(&path).map_err(normalize_key_error)
    }

    fn create_key(&self) -> Result<IdentityKey, IdentityError> {
        let mut secret = [0_u8; IDENTITY_KEY_BYTES];
        getrandom::fill(&mut secret).map_err(|_| IdentityError::KeyUnavailable)?;
        let key = IdentityKey {
            key_id: Uuid::new_v4().to_string(),
            secret,
        };
        let document = IdentityKeyDocument {
            schema_version: IDENTITY_KEY_SCHEMA_VERSION,
            key_id: key.key_id.clone(),
            secret: encode_hex(&key.secret),
        };
        let bytes = serde_json::to_vec(&document).map_err(|_| IdentityError::Invalid)?;
        atomic_publish_private(self.root, IDENTITY_KEY_FILE, &bytes)?;
        Ok(key)
    }

    pub(crate) fn derive_codex_binding(
        &self,
        codex_home: &Path,
        key: &IdentityKey,
        adapter: CodexIdentityAdapter,
    ) -> Result<ProviderIdentity, IdentityError> {
        ensure_identity_supported()?;
        verify_identity_directory(codex_home)?;
        let auth_path = codex_home.join("auth.json");
        verify_identity_file(&auth_path).map_err(|error| match error {
            IdentityError::Io(io_error) if io_error.kind() == io::ErrorKind::NotFound => {
                IdentityError::Invalid
            }
            other => other,
        })?;
        let bytes = read_bounded(&auth_path, MAX_CODEX_AUTH_BYTES)?;
        let auth: CodexAuthProjection =
            serde_json::from_slice(&bytes).map_err(|_| IdentityError::Invalid)?;
        let auth_mode = auth.auth_mode.ok_or(IdentityError::Invalid)?;
        if auth_mode != CODEX_AUTH_KIND {
            return Err(IdentityError::Unsupported);
        }
        let account_scope = auth
            .tokens
            .and_then(|tokens| tokens.account_id)
            .ok_or(IdentityError::Invalid)?;
        validate_account_scope(&account_scope)?;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key.secret)
            .map_err(|_| IdentityError::KeyUnavailable)?;
        update_length_delimited(&mut mac, FINGERPRINT_DOMAIN)?;
        update_length_delimited(&mut mac, CODEX_PROVIDER.as_bytes())?;
        update_length_delimited(&mut mac, CODEX_AUTH_KIND.as_bytes())?;
        update_length_delimited(&mut mac, adapter.version().as_bytes())?;
        update_length_delimited(&mut mac, account_scope.as_bytes())?;
        let fingerprint: [u8; FINGERPRINT_BYTES] = mac.finalize().into_bytes().into();

        Ok(ProviderIdentity {
            key_id: key.key_id.clone(),
            adapter_id: adapter.id(),
            auth_kind: CODEX_AUTH_KIND,
            fingerprint,
        })
    }

    pub(crate) fn read_marker(
        &self,
        profile_directory: &Path,
        key: &IdentityKey,
    ) -> Result<Option<ProviderIdentity>, IdentityError> {
        ensure_identity_supported()?;
        verify_identity_directory(profile_directory)?;
        let marker_path = profile_directory.join(IDENTITY_MARKER_FILE);
        match fs::symlink_metadata(&marker_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(IdentityError::Io(error)),
            Ok(_) => {}
        }
        verify_identity_file(&marker_path)?;
        let bytes = read_bounded(&marker_path, MAX_IDENTITY_MARKER_BYTES)?;
        let marker: IdentityMarkerDocument =
            serde_json::from_slice(&bytes).map_err(|_| IdentityError::Invalid)?;
        if marker.schema_version != IDENTITY_MARKER_SCHEMA_VERSION {
            return Err(IdentityError::Invalid);
        }
        if marker.key_id != key.key_id {
            return Err(IdentityError::KeyUnavailable);
        }
        if marker.adapter_id != CodexIdentityAdapter::supported_id()
            || marker.auth_kind != CODEX_AUTH_KIND
        {
            return Err(IdentityError::Unsupported);
        }
        let fingerprint = decode_fixed_hex::<FINGERPRINT_BYTES>(&marker.fingerprint)
            .ok_or(IdentityError::Invalid)?;
        Ok(Some(ProviderIdentity {
            key_id: marker.key_id,
            adapter_id: CodexIdentityAdapter::supported_id(),
            auth_kind: CODEX_AUTH_KIND,
            fingerprint,
        }))
    }

    pub(crate) fn publish_marker(
        &self,
        profile_directory: &Path,
        binding: &ProviderIdentity,
    ) -> Result<(), IdentityError> {
        ensure_identity_supported()?;
        verify_identity_directory(profile_directory)?;
        if self.marker_exists(profile_directory)? {
            return Err(IdentityError::Invalid);
        }
        let marker = IdentityMarkerDocument {
            schema_version: IDENTITY_MARKER_SCHEMA_VERSION,
            key_id: binding.key_id.clone(),
            adapter_id: binding.adapter_id.to_owned(),
            auth_kind: binding.auth_kind.to_owned(),
            fingerprint: encode_hex(&binding.fingerprint),
        };
        let bytes = serde_json::to_vec(&marker).map_err(|_| IdentityError::Invalid)?;
        atomic_publish_private(profile_directory, IDENTITY_MARKER_FILE, &bytes)
    }

    pub(crate) fn revalidate_marker(
        &self,
        profile_directory: &Path,
        key: &IdentityKey,
        current: &ProviderIdentity,
    ) -> Result<(), IdentityError> {
        ensure_identity_supported()?;
        let marker = self
            .read_marker(profile_directory, key)?
            .ok_or(IdentityError::Unverified)?;
        if marker.same_provider_identity(current) {
            Ok(())
        } else {
            Err(IdentityError::Mismatch)
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityKeyDocument {
    schema_version: u8,
    key_id: String,
    secret: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityMarkerDocument {
    schema_version: u8,
    key_id: String,
    adapter_id: String,
    auth_kind: String,
    fingerprint: String,
}

#[derive(Deserialize)]
struct CodexAuthProjection {
    auth_mode: Option<String>,
    tokens: Option<CodexTokenProjection>,
}

#[derive(Deserialize)]
struct CodexTokenProjection {
    account_id: Option<String>,
}

fn read_identity_key(path: &Path) -> Result<IdentityKey, IdentityError> {
    verify_identity_file(path)?;
    let bytes = read_bounded(path, MAX_IDENTITY_KEY_BYTES)?;
    let document: IdentityKeyDocument =
        serde_json::from_slice(&bytes).map_err(|_| IdentityError::KeyUnavailable)?;
    if document.schema_version != IDENTITY_KEY_SCHEMA_VERSION {
        return Err(IdentityError::KeyUnavailable);
    }
    let parsed_id = Uuid::parse_str(&document.key_id).map_err(|_| IdentityError::KeyUnavailable)?;
    if parsed_id.to_string() != document.key_id {
        return Err(IdentityError::KeyUnavailable);
    }
    let secret = decode_fixed_hex::<IDENTITY_KEY_BYTES>(&document.secret)
        .ok_or(IdentityError::KeyUnavailable)?;
    Ok(IdentityKey {
        key_id: document.key_id,
        secret,
    })
}

fn normalize_key_error(error: IdentityError) -> IdentityError {
    let _ = error;
    IdentityError::KeyUnavailable
}

#[cfg(unix)]
const fn ensure_identity_supported() -> Result<(), IdentityError> {
    Ok(())
}

#[cfg(not(unix))]
const fn ensure_identity_supported() -> Result<(), IdentityError> {
    Err(IdentityError::Unsupported)
}

fn validate_account_scope(scope: &str) -> Result<(), IdentityError> {
    if scope.is_empty()
        || scope.len() > MAX_ACCOUNT_SCOPE_BYTES
        || !scope.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(IdentityError::Invalid);
    }
    Ok(())
}

fn update_length_delimited(mac: &mut HmacSha256, value: &[u8]) -> Result<(), IdentityError> {
    let length = u64::try_from(value.len()).map_err(|_| IdentityError::Invalid)?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, IdentityError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(IdentityError::Invalid);
    }
    Ok(bytes)
}

fn atomic_publish_private(root: &Path, name: &str, bytes: &[u8]) -> Result<(), IdentityError> {
    atomic_publish_private_with_sync(root, name, bytes, sync_directory)
}

fn atomic_publish_private_with_sync(
    root: &Path,
    name: &str,
    bytes: &[u8],
    sync_parent: impl FnOnce(&Path) -> Result<(), IdentityError>,
) -> Result<(), IdentityError> {
    verify_identity_directory(root)?;
    let destination = root.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => return Err(IdentityError::Invalid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(IdentityError::Io(error)),
    }

    let temporary = root.join(format!(".{name}.{}.tmp", Uuid::new_v4()));
    write_private_new(&temporary, bytes)?;
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(IdentityError::Io(error));
    }
    if sync_parent(root).is_err() {
        let complete = verify_identity_file(&destination)
            .and_then(|()| read_bounded(&destination, bytes.len()))
            .is_ok_and(|visible| visible == bytes);
        if complete {
            return Err(IdentityError::CommitUncertain);
        }
        return Err(IdentityError::Invalid);
    }
    Ok(())
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    let mut options = private_open_options();
    let mut file = options.write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    verify_identity_file(path)
}

#[cfg(unix)]
fn private_open_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.mode(0o600);
    options
}

#[cfg(not(unix))]
fn private_open_options() -> OpenOptions {
    OpenOptions::new()
}

#[cfg(unix)]
fn verify_identity_directory(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(IdentityError::Invalid);
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_identity_directory(path: &Path) -> Result<(), IdentityError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(IdentityError::Invalid);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_identity_file(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(IdentityError::Invalid);
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_identity_file(path: &Path) -> Result<(), IdentityError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(IdentityError::Invalid);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), IdentityError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_fixed_hex<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    if encoded.len() != N * 2 || !encoded.is_ascii() {
        return None;
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(decoded)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::*;

    fn temporary_root(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "calcifer-identity-{test_name}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ))
    }

    #[cfg(unix)]
    #[test]
    fn private_fingerprint_is_stable_without_persisting_provider_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("fingerprint");
        create_private_directory(&root)?;
        let profile = root.join("profile");
        let home = profile.join("home");
        create_private_directory(&profile)?;
        create_private_directory(&home)?;

        let first_scope = Uuid::new_v4().to_string();
        write_auth(&home, &first_scope)?;
        let store = IdentityStore::new(&root);
        let key = store.load_or_create_key(false)?;
        let first = store.derive_codex_binding(&home, &key, CodexIdentityAdapter::for_test())?;
        let repeated = store.derive_codex_binding(&home, &key, CodexIdentityAdapter::for_test())?;
        assert!(first.same_provider_identity(&repeated));

        store.publish_marker(&profile, &first)?;
        let marker = fs::read(profile.join(IDENTITY_MARKER_FILE))?;
        let key_file = fs::read(root.join(IDENTITY_KEY_FILE))?;
        assert!(!contains(&marker, &first_scope));
        assert!(!contains(&key_file, &first_scope));

        let second_scope = Uuid::new_v4().to_string();
        fs::remove_file(home.join("auth.json"))?;
        write_auth(&home, &second_scope)?;
        let second = store.derive_codex_binding(&home, &key, CodexIdentityAdapter::for_test())?;
        assert!(!first.same_provider_identity(&second));
        assert!(!contains(&marker, &second_scope));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn missing_key_is_not_recreated_over_existing_bindings()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("missing-key");
        create_private_directory(&root)?;
        let store = IdentityStore::new(&root);

        let error = store
            .load_or_create_key(true)
            .err()
            .ok_or("missing key must fail closed")?;
        assert_eq!(error.code(), "identity_key_unavailable");
        assert!(!root.join(IDENTITY_KEY_FILE).exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn malformed_auth_is_redacted_and_never_publishes_a_marker()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("malformed-auth");
        create_private_directory(&root)?;
        let profile = root.join("profile");
        let home = profile.join("home");
        create_private_directory(&profile)?;
        create_private_directory(&home)?;
        let sensitive = format!("{}@example.invalid", Uuid::new_v4());
        write_private(&home.join("auth.json"), sensitive.as_bytes())?;

        let store = IdentityStore::new(&root);
        let key = store.load_or_create_key(false)?;
        let error = store
            .derive_codex_binding(&home, &key, CodexIdentityAdapter::for_test())
            .err()
            .ok_or("malformed auth must fail")?;
        assert_eq!(error.code(), "provider_identity_invalid");
        assert!(!error.safe_message().contains(&sensitive));
        assert!(!profile.join(IDENTITY_MARKER_FILE).exists());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_and_oversized_auth_fail_closed_without_disclosure()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("unsupported-auth");
        create_private_directory(&root)?;
        let home = root.join("home");
        create_private_directory(&home)?;
        let sensitive = Uuid::new_v4().to_string();
        let unsupported = serde_json::json!({
            "auth_mode": "api_key",
            "tokens": { "account_id": sensitive }
        });
        write_private(
            &home.join("auth.json"),
            serde_json::to_vec(&unsupported)?.as_slice(),
        )?;
        let store = IdentityStore::new(&root);
        let key = store.load_or_create_key(false)?;
        let unsupported_error = store
            .derive_codex_binding(&home, &key, CodexIdentityAdapter::for_test())
            .err()
            .ok_or("unsupported auth mode must fail")?;
        assert_eq!(unsupported_error.code(), "provider_identity_unsupported");
        assert!(!unsupported_error.safe_message().contains(&sensitive));

        fs::remove_file(home.join("auth.json"))?;
        write_private(
            &home.join("auth.json"),
            &vec![b' '; MAX_CODEX_AUTH_BYTES + 1],
        )?;
        let oversized_error = store
            .derive_codex_binding(&home, &key, CodexIdentityAdapter::for_test())
            .err()
            .ok_or("oversized auth must fail")?;
        assert_eq!(oversized_error.code(), "provider_identity_invalid");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn identity_publication_reports_commit_uncertain_after_complete_rename()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("commit-uncertain");
        create_private_directory(&root)?;
        let bytes = b"complete-private-state";

        let error = atomic_publish_private_with_sync(&root, ".synthetic-identity", bytes, |_| {
            Err(IdentityError::Io(io::Error::other("injected sync failure")))
        })
        .err()
        .ok_or("directory sync failure must be reported")?;
        assert_eq!(error.code(), "identity_commit_uncertain");
        assert_eq!(fs::read(root.join(".synthetic-identity"))?, bytes);
        assert!(!fs::read_dir(&root)?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.ends_with(".tmp"))
        }));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn stale_temporary_marker_is_ignored_by_readers() -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("stale-marker-temp");
        create_private_directory(&root)?;
        let profile = root.join("profile");
        create_private_directory(&profile)?;
        write_private(
            &profile.join(format!(".{IDENTITY_MARKER_FILE}.{}.tmp", Uuid::new_v4())),
            b"incomplete",
        )?;
        let store = IdentityStore::new(&root);
        let key = store.load_or_create_key(false)?;

        assert!(store.read_marker(&profile, &key)?.is_none());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn replaced_key_cannot_validate_an_existing_marker() -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("replaced-key");
        let replacement_root = temporary_root("replacement-key-source");
        create_private_directory(&root)?;
        create_private_directory(&replacement_root)?;
        let profile = root.join("profile");
        let home = profile.join("home");
        create_private_directory(&profile)?;
        create_private_directory(&home)?;
        write_auth(&home, &Uuid::new_v4().to_string())?;

        let store = IdentityStore::new(&root);
        let key = store.load_or_create_key(false)?;
        let binding = store.derive_codex_binding(&home, &key, CodexIdentityAdapter::for_test())?;
        store.publish_marker(&profile, &binding)?;

        let replacement_store = IdentityStore::new(&replacement_root);
        replacement_store.load_or_create_key(false)?;
        fs::remove_file(root.join(IDENTITY_KEY_FILE))?;
        write_private(
            &root.join(IDENTITY_KEY_FILE),
            &fs::read(replacement_root.join(IDENTITY_KEY_FILE))?,
        )?;
        let replacement_key = store.load_key()?;
        let error = store
            .read_marker(&profile, &replacement_key)
            .err()
            .ok_or("replacement key must not validate an old marker")?;
        assert_eq!(error.code(), "identity_key_unavailable");

        fs::remove_dir_all(root)?;
        fs::remove_dir_all(replacement_root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_key_metadata_is_reported_as_key_unavailable() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for unsafe_kind in ["mode", "hard-link", "symlink"] {
            let root = temporary_root(unsafe_kind);
            create_private_directory(&root)?;
            let store = IdentityStore::new(&root);
            store.load_or_create_key(false)?;
            let key_path = root.join(IDENTITY_KEY_FILE);

            match unsafe_kind {
                "mode" => {
                    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))?;
                }
                "hard-link" => {
                    fs::hard_link(&key_path, root.join("linked-key"))?;
                }
                "symlink" => {
                    let original = root.join("original-key");
                    fs::rename(&key_path, &original)?;
                    symlink(&original, &key_path)?;
                }
                _ => return Err("unknown test case".into()),
            }

            let error = store
                .load_key()
                .err()
                .ok_or("unsafe key metadata must fail")?;
            assert_eq!(error.code(), "identity_key_unavailable");
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn create_private_directory(path: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;

        fs::DirBuilder::new().mode(0o700).create(path)
    }

    #[cfg(unix)]
    fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    #[cfg(unix)]
    fn write_auth(home: &std::path::Path, scope: &str) -> std::io::Result<()> {
        let document = serde_json::json!({
            "auth_mode": "chatgpt",
            "tokens": { "account_id": scope }
        });
        write_private(
            &home.join("auth.json"),
            serde_json::to_vec(&document)?.as_slice(),
        )
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn identity_store_fails_closed_without_verified_platform_acl_support() {
        let store = IdentityStore::new(Path::new("unused-non-unix-identity-root"));
        let error = match store.load_or_create_key(false) {
            Err(error) => error,
            Ok(_) => panic!("unsupported platforms must fail before filesystem access"),
        };
        assert_eq!(error.code(), "provider_identity_unsupported");
    }
}
