//! Fail-closed compatibility gate for cross-profile Codex thread handoff.

use std::fmt;
#[cfg(any(
    all(test, unix),
    all(
        feature = "internal-supervisor-fixture",
        any(target_os = "linux", target_os = "macos")
    )
))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(any(
    all(test, unix),
    all(
        feature = "internal-supervisor-fixture",
        any(target_os = "linux", target_os = "macos")
    )
))]
use std::time::Duration;

use serde_json::Value;

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
use super::supervisor::ProviderLaunchAuthorization;

#[cfg(unix)]
mod runtime;
#[cfg(unix)]
pub(in crate::providers::codex) use runtime::PinnedExecutableStage;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(in crate::providers::codex) use runtime::PinnedStageError;
#[cfg(all(test, unix))]
pub(in crate::providers::codex) use runtime::{PinnedStageCleanupFault, PinnedStageCreateFailure};

#[cfg(not(unix))]
pub(in crate::providers::codex) struct PinnedExecutableStage {
    _private: (),
}

/// Capability proving that an exact Codex build passed schema, fork, and
/// remote-TUI runtime probes in an isolated credential-free workspace.
///
/// Its constructor is private. Future handoff code can consume this value but
/// cannot mint it from a version string or schema inspection alone.
#[allow(dead_code)] // Consumed by the handoff transaction introduced in issue #33.
pub(crate) struct CodexHandoffCapability {
    executable: PinnedExecutableStage,
}

#[derive(Eq, PartialEq)]
struct CodexExecutableIdentity {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    digest: [u8; 32],
}

#[allow(dead_code)] // Consumed by the handoff transaction introduced in issue #33.
impl CodexHandoffCapability {
    pub(crate) const fn id(&self) -> &'static str {
        "codex-handoff/0.144.4/v1"
    }

    pub(crate) const fn version(&self) -> &'static str {
        "0.144.4"
    }

    pub(in crate::providers::codex) fn into_pinned_executable(self) -> PinnedExecutableStage {
        self.executable
    }
}

#[cfg(all(test, unix))]
pub(super) struct TestCompatibilityCapability {
    executable: CodexExecutableIdentity,
}

#[cfg(all(test, unix))]
impl TestCompatibilityCapability {
    pub(super) fn capture(executable: &Path) -> Result<Self, runtime::PinnedStageError> {
        runtime::capture_test_compatibility(executable).map(|executable| Self { executable })
    }

    pub(super) fn pin_in(
        self,
        parent: &Path,
    ) -> Result<CodexHandoffCapability, runtime::PinnedStageCreateFailure> {
        runtime::pin_test_compatibility(self.executable, parent)
            .map(|executable| CodexHandoffCapability { executable })
    }

    /// Captures and pins the fixture under one caller-supplied budget. The
    /// seam preserves the production capture error and projects any partial
    /// stage through the normal retained compatibility owner.
    pub(super) fn capture_and_pin_authorized(
        executable: &Path,
        parent: &Path,
        timeout: Duration,
    ) -> Result<CodexHandoffCapability, CodexHandoffFailure> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or(CodexHandoffError::Timeout)?;
        let executable = runtime::capture_test_compatibility_until(executable, deadline)?;
        runtime::pin_test_compatibility_until(executable, parent, deadline)
            .map(|executable| CodexHandoffCapability { executable })
            .map_err(Into::into)
    }

    pub(super) fn pin_in_with_root_sync_failure(
        self,
        parent: &Path,
    ) -> Result<CodexHandoffCapability, runtime::PinnedStageCreateFailure> {
        runtime::pin_test_compatibility_with_root_sync_failure(self.executable, parent)
            .map(|executable| CodexHandoffCapability { executable })
    }

    pub(super) fn pin_in_with_parent_sync_failure(
        self,
        parent: &Path,
    ) -> Result<CodexHandoffCapability, runtime::PinnedStageCreateFailure> {
        runtime::pin_test_compatibility_with_parent_sync_failure(self.executable, parent)
            .map(|executable| CodexHandoffCapability { executable })
    }
}

/// Redacted compatibility failure returned before handoff is authorized.
#[allow(dead_code)] // Surfaced by the handoff transaction introduced in issue #33.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexHandoffError {
    Unsupported,
    Protocol,
    Timeout,
    Transport,
    Spawn,
}

/// A compatibility failure that retains any filesystem authority created
/// before the failure became observable.
#[must_use = "handoff failure can retain staged filesystem ownership"]
pub(crate) struct CodexHandoffFailure {
    error: CodexHandoffError,
    cleanup_error: Option<CodexHandoffError>,
    #[cfg(unix)]
    retained: Option<runtime::CodexHandoffRetention>,
}

impl CodexHandoffFailure {
    #[cfg(unix)]
    fn with_retained(error: CodexHandoffError, retained: runtime::CodexHandoffRetention) -> Self {
        Self {
            error,
            cleanup_error: None,
            retained: Some(retained),
        }
    }

    pub(crate) const fn error(&self) -> CodexHandoffError {
        self.error
    }

    pub(crate) const fn has_retained_ownership(&self) -> bool {
        #[cfg(unix)]
        {
            self.retained.is_some()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    pub(crate) const fn cleanup_error(&self) -> Option<CodexHandoffError> {
        self.cleanup_error
    }

    /// Resolves every exact filesystem/process owner retained by a failed
    /// compatibility probe. A failed cleanup returns the same original probe
    /// error together with the still-owned retry state; cleanup errors never
    /// overwrite the operation failure.
    #[cfg(unix)]
    #[expect(
        clippy::boxed_local,
        reason = "the compatibility failure can retain large recursive cleanup ownership"
    )]
    pub(crate) fn resolve(
        self: Box<Self>,
        deadline: std::time::Instant,
    ) -> Result<CodexHandoffResolution, Box<Self>> {
        let Self {
            error,
            cleanup_error,
            retained,
        } = *self;
        let Some(retained) = retained else {
            return Ok(CodexHandoffResolution {
                error,
                cleanup_error,
            });
        };
        match runtime::resolve_handoff_retention(retained, deadline) {
            Ok(()) => Ok(CodexHandoffResolution {
                error,
                cleanup_error,
            }),
            Err(failure) => Err(Box::new(Self {
                error,
                cleanup_error: cleanup_error.or(Some(failure.error)),
                retained: Some(failure.retained),
            })),
        }
    }
}

impl From<CodexHandoffError> for CodexHandoffFailure {
    fn from(error: CodexHandoffError) -> Self {
        Self {
            error,
            cleanup_error: None,
            #[cfg(unix)]
            retained: None,
        }
    }
}

impl fmt::Debug for CodexHandoffFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexHandoffFailure")
            .field("error", &self.error)
            .field("cleanup_error", &self.cleanup_error)
            .field("retained", &self.has_retained_ownership())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for CodexHandoffFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error().fmt(formatter)
    }
}

impl std::error::Error for CodexHandoffFailure {}

/// Proof that a failed compatibility attempt retains no process or filesystem
/// cleanup authority. The original operation failure remains observable after
/// cleanup succeeds.
#[cfg(unix)]
#[must_use = "resolved compatibility cleanup must be projected to startup"]
pub(crate) struct CodexHandoffResolution {
    error: CodexHandoffError,
    cleanup_error: Option<CodexHandoffError>,
}

#[cfg(unix)]
impl CodexHandoffResolution {
    pub(crate) const fn error(&self) -> CodexHandoffError {
        self.error
    }

    pub(crate) const fn cleanup_error(&self) -> Option<CodexHandoffError> {
        self.cleanup_error
    }

    pub(crate) const fn release(self) -> CodexHandoffError {
        self.error
    }
}

#[cfg(unix)]
impl fmt::Debug for CodexHandoffResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexHandoffResolution")
            .field("error", &self.error)
            .field("cleanup_error", &self.cleanup_error)
            .finish()
    }
}

impl fmt::Display for CodexHandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported => "the installed Codex does not support guarded thread handoff",
            Self::Protocol => "the Codex handoff compatibility response was invalid",
            Self::Timeout => "the Codex handoff compatibility probe timed out",
            Self::Transport => "the Codex handoff compatibility transport failed",
            Self::Spawn => "the Codex handoff compatibility probe could not be started",
        })
    }
}

impl std::error::Error for CodexHandoffError {}

/// Runs the complete private compatibility gate without reading or mutating a
/// Calcifer profile, conversation binding, credential, or user rollout.
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
#[allow(dead_code)] // Consumed by the handoff transaction introduced in issue #33.
pub(crate) fn verify_codex_handoff_compatibility(
    _authorization: &ProviderLaunchAuthorization,
    codex_executable: &Path,
    timeout: Duration,
) -> Result<CodexHandoffCapability, CodexHandoffFailure> {
    runtime::verify(codex_executable, timeout)
}

#[cfg(all(test, unix))]
fn verify_codex_handoff_compatibility_for_test(
    codex_executable: &Path,
    timeout: Duration,
) -> Result<CodexHandoffCapability, CodexHandoffFailure> {
    runtime::verify(codex_executable, timeout)
}

#[cfg(all(test, unix))]
pub(super) fn compatibility_verification_attempts_for_test() -> usize {
    runtime::verification_attempts_for_test()
}

const JSON_SCHEMA_DRAFT_07: &str = "http://json-schema.org/draft-07/schema#";
const PROTOCOL_SCHEMA_TITLE: &str = "CodexAppServerProtocolV2";
const JSONRPC_ERROR_TITLE: &str = "JSONRPCError";
const JSONRPC_ERROR_BODY_TITLE: &str = "JSONRPCErrorError";
const JSONRPC_ERROR_DESCRIPTION: &str = "A response to a request that indicates an error occurred.";
const APPROVALS_REVIEWER_DESCRIPTION: &str =
    "Reviewer currently used for approval requests on this thread.";
const SANDBOX_RESPONSE_DESCRIPTION: &str = "Legacy sandbox policy retained for compatibility. Experimental clients should prefer `activePermissionProfile` for profile provenance.";
const FORK_PATH_DESCRIPTION: &str = "[UNSTABLE] Specify the rollout path to fork from. If specified, the thread_id param will be ignored.";
const RESUME_PATH_DESCRIPTION: &str = "[UNSTABLE] Specify the rollout path to resume from. If specified for a non-running thread, the thread_id param will be ignored. If thread_id identifies a running thread, the path must match the active rollout path.";
const RESPONSE_REQUIRED: &[&str] = &[
    "approvalPolicy",
    "approvalsReviewer",
    "cwd",
    "model",
    "modelProvider",
    "sandbox",
    "thread",
];
const THREAD_REQUIRED: &[&str] = &[
    "cliVersion",
    "createdAt",
    "cwd",
    "ephemeral",
    "id",
    "modelProvider",
    "preview",
    "sessionId",
    "source",
    "status",
    "turns",
    "updatedAt",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandoffSchemaContract {
    _private: (),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandoffSchemaError {
    Malformed,
}

fn validate_handoff_schema_pair(
    default_schema: &Value,
    experimental_schema: &Value,
    default_error_schema: &Value,
    default_error_body_schema: &Value,
    experimental_error_schema: &Value,
    experimental_error_body_schema: &Value,
) -> Result<HandoffSchemaContract, HandoffSchemaError> {
    validate_schema_header(default_schema)?;
    validate_schema_header(experimental_schema)?;

    validate_thread_params(default_schema, "ThreadForkParams", None)?;
    validate_thread_params(default_schema, "ThreadResumeParams", None)?;
    validate_thread_params(
        experimental_schema,
        "ThreadForkParams",
        Some(FORK_PATH_DESCRIPTION),
    )?;
    validate_thread_params(
        experimental_schema,
        "ThreadResumeParams",
        Some(RESUME_PATH_DESCRIPTION),
    )?;

    for schema in [default_schema, experimental_schema] {
        validate_thread_response(schema, "ThreadForkResponse")?;
        validate_thread_response(schema, "ThreadResumeResponse")?;
        validate_thread(schema)?;
    }
    for (error_schema, error_body_schema) in [
        (default_error_schema, default_error_body_schema),
        (experimental_error_schema, experimental_error_body_schema),
    ] {
        validate_jsonrpc_error_schema(error_schema)?;
        validate_jsonrpc_error_body_schema(error_body_schema)?;
    }

    Ok(HandoffSchemaContract { _private: () })
}

fn validate_jsonrpc_error_schema(schema: &Value) -> Result<(), HandoffSchemaError> {
    let error_body = jsonrpc_error_body_projection();
    let expected = serde_json::json!({
        "$schema": JSON_SCHEMA_DRAFT_07,
        "title": JSONRPC_ERROR_TITLE,
        "description": JSONRPC_ERROR_DESCRIPTION,
        "type": "object",
        "required": ["error", "id"],
        "properties": {
            "error": { "$ref": "#/definitions/JSONRPCErrorError" },
            "id": { "$ref": "#/definitions/RequestId" }
        },
        "definitions": {
            "JSONRPCErrorError": error_body,
            "RequestId": {
                "anyOf": [
                    { "type": "string" },
                    { "type": "integer", "format": "int64" }
                ]
            }
        }
    });
    if schema == &expected {
        Ok(())
    } else {
        Err(HandoffSchemaError::Malformed)
    }
}

fn validate_jsonrpc_error_body_schema(schema: &Value) -> Result<(), HandoffSchemaError> {
    let expected_body = jsonrpc_error_body_projection();
    let expected = serde_json::json!({
        "$schema": JSON_SCHEMA_DRAFT_07,
        "title": JSONRPC_ERROR_BODY_TITLE,
        "type": "object",
        "required": ["code", "message"],
        "properties": expected_body["properties"].clone()
    });
    if schema == &expected {
        Ok(())
    } else {
        Err(HandoffSchemaError::Malformed)
    }
}

fn jsonrpc_error_body_projection() -> Value {
    serde_json::json!({
        "type": "object",
        "required": ["code", "message"],
        "properties": {
            "code": { "type": "integer", "format": "int64" },
            "data": true,
            "message": { "type": "string" }
        }
    })
}

fn validate_schema_header(schema: &Value) -> Result<(), HandoffSchemaError> {
    if schema.get("$schema").and_then(Value::as_str) != Some(JSON_SCHEMA_DRAFT_07)
        || schema.get("title").and_then(Value::as_str) != Some(PROTOCOL_SCHEMA_TITLE)
        || schema
            .get("definitions")
            .and_then(Value::as_object)
            .is_none()
    {
        return Err(HandoffSchemaError::Malformed);
    }
    Ok(())
}

fn validate_thread_params(
    schema: &Value,
    name: &str,
    expected_path_description: Option<&str>,
) -> Result<(), HandoffSchemaError> {
    let definition = definition(schema, name)?;
    if definition.get("title").and_then(Value::as_str) != Some(name)
        || definition.get("type").and_then(Value::as_str) != Some("object")
        || !required_matches(definition, &["threadId"])
        || property(definition, "threadId") != Some(&serde_json::json!({ "type": "string" }))
    {
        return Err(HandoffSchemaError::Malformed);
    }

    match expected_path_description {
        None if property(definition, "path").is_some() => Err(HandoffSchemaError::Malformed),
        None => Ok(()),
        Some(description)
            if property(definition, "path")
                == Some(&serde_json::json!({
                    "description": description,
                    "default": null,
                    "type": ["string", "null"]
                })) =>
        {
            Ok(())
        }
        Some(_) => Err(HandoffSchemaError::Malformed),
    }
}

fn validate_thread_response(schema: &Value, name: &str) -> Result<(), HandoffSchemaError> {
    let definition = definition(schema, name)?;
    if definition.get("title").and_then(Value::as_str) != Some(name)
        || definition.get("type").and_then(Value::as_str) != Some("object")
        || !required_matches(definition, RESPONSE_REQUIRED)
        || property(definition, "approvalPolicy")
            != Some(&serde_json::json!({ "$ref": "#/definitions/AskForApproval" }))
        || property(definition, "approvalsReviewer")
            != Some(&serde_json::json!({
                "description": APPROVALS_REVIEWER_DESCRIPTION,
                "allOf": [{ "$ref": "#/definitions/ApprovalsReviewer" }]
            }))
        || property(definition, "cwd")
            != Some(&serde_json::json!({ "$ref": "#/definitions/AbsolutePathBuf" }))
        || property(definition, "model") != Some(&serde_json::json!({ "type": "string" }))
        || property(definition, "modelProvider") != Some(&serde_json::json!({ "type": "string" }))
        || property(definition, "sandbox")
            != Some(&serde_json::json!({
                "description": SANDBOX_RESPONSE_DESCRIPTION,
                "allOf": [{ "$ref": "#/definitions/SandboxPolicy" }]
            }))
        || property(definition, "thread")
            != Some(&serde_json::json!({ "$ref": "#/definitions/Thread" }))
    {
        return Err(HandoffSchemaError::Malformed);
    }
    Ok(())
}

fn validate_thread(schema: &Value) -> Result<(), HandoffSchemaError> {
    let definition = definition(schema, "Thread")?;
    if definition.get("type").and_then(Value::as_str) != Some("object")
        || !required_matches(definition, THREAD_REQUIRED)
        || !property_has_type(definition, "id", &Value::String("string".to_owned()))
        || !property_has_type(definition, "sessionId", &Value::String("string".to_owned()))
        || !property_has_type(
            definition,
            "forkedFromId",
            &serde_json::json!(["string", "null"]),
        )
        || !property_has_type(definition, "path", &serde_json::json!(["string", "null"]))
    {
        return Err(HandoffSchemaError::Malformed);
    }
    Ok(())
}

fn definition<'a>(schema: &'a Value, name: &str) -> Result<&'a Value, HandoffSchemaError> {
    schema
        .get("definitions")
        .and_then(|definitions| definitions.get(name))
        .filter(|definition| definition.is_object())
        .ok_or(HandoffSchemaError::Malformed)
}

fn property<'a>(definition: &'a Value, name: &str) -> Option<&'a Value> {
    definition
        .get("properties")
        .and_then(|properties| properties.get(name))
}

fn property_has_type(definition: &Value, name: &str, expected: &Value) -> bool {
    property(definition, name).and_then(|property| property.get("type")) == Some(expected)
}

fn required_matches(definition: &Value, expected: &[&str]) -> bool {
    let Some(required) = definition.get("required").and_then(Value::as_array) else {
        return false;
    };
    required.len() == expected.len()
        && expected.iter().all(|expected_name| {
            required
                .iter()
                .filter(|candidate| candidate.as_str() == Some(expected_name))
                .count()
                == 1
        })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::{Value, json};

    use super::*;

    fn schema_pair() -> (Value, Value) {
        let thread = json!({
            "type": "object",
            "required": [
                "cliVersion", "createdAt", "cwd", "ephemeral", "id",
                "modelProvider", "preview", "sessionId", "source", "status",
                "turns", "updatedAt"
            ],
            "properties": {
                "id": { "type": "string" },
                "sessionId": { "type": "string" },
                "forkedFromId": { "type": ["string", "null"] },
                "path": { "type": ["string", "null"] }
            }
        });
        let response = |title: &str| {
            json!({
                "title": title,
                "type": "object",
                "required": [
                    "approvalPolicy", "approvalsReviewer", "cwd", "model",
                    "modelProvider", "sandbox", "thread"
                ],
                "properties": {
                    "approvalPolicy": { "$ref": "#/definitions/AskForApproval" },
                    "approvalsReviewer": {
                        "description": APPROVALS_REVIEWER_DESCRIPTION,
                        "allOf": [{ "$ref": "#/definitions/ApprovalsReviewer" }]
                    },
                    "cwd": { "$ref": "#/definitions/AbsolutePathBuf" },
                    "model": { "type": "string" },
                    "modelProvider": { "type": "string" },
                    "sandbox": {
                        "description": SANDBOX_RESPONSE_DESCRIPTION,
                        "allOf": [{ "$ref": "#/definitions/SandboxPolicy" }]
                    },
                    "thread": { "$ref": "#/definitions/Thread" }
                }
            })
        };
        let stable_params = |title: &str| {
            json!({
                "title": title,
                "type": "object",
                "required": ["threadId"],
                "properties": {
                    "threadId": { "type": "string" }
                }
            })
        };

        let default_schema = json!({
            "$schema": JSON_SCHEMA_DRAFT_07,
            "title": PROTOCOL_SCHEMA_TITLE,
            "definitions": {
                "Thread": thread.clone(),
                "ThreadForkParams": stable_params("ThreadForkParams"),
                "ThreadForkResponse": response("ThreadForkResponse"),
                "ThreadResumeParams": stable_params("ThreadResumeParams"),
                "ThreadResumeResponse": response("ThreadResumeResponse")
            }
        });
        let mut experimental_schema = default_schema.clone();
        experimental_schema["definitions"]["ThreadForkParams"]["properties"]["path"] = json!({
            "description": FORK_PATH_DESCRIPTION,
            "default": null,
            "type": ["string", "null"]
        });
        experimental_schema["definitions"]["ThreadResumeParams"]["properties"]["path"] = json!({
            "description": "[UNSTABLE] Specify the rollout path to resume from. If specified for a non-running thread, the thread_id param will be ignored. If thread_id identifies a running thread, the path must match the active rollout path.",
            "default": null,
            "type": ["string", "null"]
        });
        (default_schema, experimental_schema)
    }

    fn error_schema_pair() -> (Value, Value, Value, Value) {
        let error_body = json!({
            "type": "object",
            "required": ["code", "message"],
            "properties": {
                "code": { "type": "integer", "format": "int64" },
                "data": true,
                "message": { "type": "string" }
            }
        });
        let error_schema = json!({
            "$schema": JSON_SCHEMA_DRAFT_07,
            "title": JSONRPC_ERROR_TITLE,
            "description": JSONRPC_ERROR_DESCRIPTION,
            "type": "object",
            "required": ["error", "id"],
            "properties": {
                "error": { "$ref": "#/definitions/JSONRPCErrorError" },
                "id": { "$ref": "#/definitions/RequestId" }
            },
            "definitions": {
                "JSONRPCErrorError": error_body.clone(),
                "RequestId": {
                    "anyOf": [
                        { "type": "string" },
                        { "type": "integer", "format": "int64" }
                    ]
                }
            }
        });
        let error_body_schema = json!({
            "$schema": JSON_SCHEMA_DRAFT_07,
            "title": JSONRPC_ERROR_BODY_TITLE,
            "type": "object",
            "required": ["code", "message"],
            "properties": error_body["properties"].clone()
        });
        (
            error_schema.clone(),
            error_body_schema.clone(),
            error_schema,
            error_body_schema,
        )
    }

    fn validate_protocol_pair(
        default_schema: &Value,
        experimental_schema: &Value,
    ) -> Result<HandoffSchemaContract, HandoffSchemaError> {
        let (
            default_error_schema,
            default_error_body_schema,
            experimental_error_schema,
            experimental_error_body_schema,
        ) = error_schema_pair();
        validate_handoff_schema_pair(
            default_schema,
            experimental_schema,
            &default_error_schema,
            &default_error_body_schema,
            &experimental_error_schema,
            &experimental_error_body_schema,
        )
    }

    #[test]
    fn accepts_the_exact_v0_144_4_handoff_projection() {
        let (default_schema, experimental_schema) = schema_pair();

        assert_eq!(
            validate_protocol_pair(&default_schema, &experimental_schema),
            Ok(HandoffSchemaContract { _private: () })
        );
    }

    #[test]
    fn rejects_a_default_schema_that_authorizes_fork_by_path() {
        let (mut default_schema, experimental_schema) = schema_pair();
        default_schema["definitions"]["ThreadForkParams"]["properties"]["path"] =
            experimental_schema["definitions"]["ThreadForkParams"]["properties"]["path"].clone();

        assert_eq!(
            validate_protocol_pair(&default_schema, &experimental_schema),
            Err(HandoffSchemaError::Malformed)
        );
    }

    #[test]
    fn rejects_mutated_experimental_fork_path_contracts() {
        for replacement in [
            Value::Null,
            json!({
                "description": "stable path",
                "default": null,
                "type": ["string", "null"]
            }),
            json!({
                "description": FORK_PATH_DESCRIPTION,
                "default": "",
                "type": ["string", "null"]
            }),
            json!({
                "description": FORK_PATH_DESCRIPTION,
                "default": null,
                "type": "string"
            }),
        ] {
            let (default_schema, mut experimental_schema) = schema_pair();
            experimental_schema["definitions"]["ThreadForkParams"]["properties"]["path"] =
                replacement;

            assert_eq!(
                validate_protocol_pair(&default_schema, &experimental_schema),
                Err(HandoffSchemaError::Malformed)
            );
        }
    }

    #[test]
    fn rejects_malformed_fork_resume_and_thread_response_projections() {
        for pointer in [
            "/definitions/ThreadForkResponse/properties/approvalPolicy",
            "/definitions/ThreadForkResponse/properties/approvalsReviewer",
            "/definitions/ThreadForkResponse/properties/cwd",
            "/definitions/ThreadForkResponse/properties/model",
            "/definitions/ThreadForkResponse/properties/modelProvider",
            "/definitions/ThreadForkResponse/properties/sandbox",
            "/definitions/ThreadForkResponse/properties/thread",
            "/definitions/ThreadResumeResponse/properties/approvalPolicy",
            "/definitions/ThreadResumeResponse/properties/approvalsReviewer",
            "/definitions/ThreadResumeResponse/properties/cwd",
            "/definitions/ThreadResumeResponse/properties/model",
            "/definitions/ThreadResumeResponse/properties/modelProvider",
            "/definitions/ThreadResumeResponse/properties/sandbox",
            "/definitions/ThreadResumeResponse/properties/thread",
            "/definitions/Thread/properties/id",
            "/definitions/Thread/properties/sessionId",
            "/definitions/Thread/properties/forkedFromId",
            "/definitions/Thread/properties/path",
        ] {
            let (default_schema, mut experimental_schema) = schema_pair();
            let slot = experimental_schema
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("fixture pointer must exist: {pointer}"));
            *slot = Value::Null;

            assert_eq!(
                validate_protocol_pair(&default_schema, &experimental_schema),
                Err(HandoffSchemaError::Malformed),
                "mutation at {pointer} must fail closed"
            );
        }
    }

    #[test]
    fn rejects_mutated_jsonrpc_error_envelopes_and_bodies() {
        for (document, pointer, replacement) in [
            (
                0,
                "/definitions/JSONRPCErrorError/properties/code/format",
                json!("int32"),
            ),
            (0, "/definitions/RequestId/anyOf/1/type", json!("number")),
            (1, "/properties/data", json!({ "type": "object" })),
            (2, "/required", json!(["error"])),
            (3, "/properties/message/type", json!("number")),
        ] {
            let (default_schema, experimental_schema) = schema_pair();
            let (
                mut default_error,
                mut default_error_body,
                mut experimental_error,
                mut experimental_error_body,
            ) = error_schema_pair();
            let target = match document {
                0 => &mut default_error,
                1 => &mut default_error_body,
                2 => &mut experimental_error,
                3 => &mut experimental_error_body,
                _ => unreachable!(),
            };
            *target
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("fixture pointer must exist: {pointer}")) = replacement;

            assert_eq!(
                validate_handoff_schema_pair(
                    &default_schema,
                    &experimental_schema,
                    &default_error,
                    &default_error_body,
                    &experimental_error,
                    &experimental_error_body,
                ),
                Err(HandoffSchemaError::Malformed),
                "error schema mutation {document}:{pointer} must fail closed"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires the pinned official Codex 0.144.4 package"]
    fn packaged_codex_0_144_4_passes_the_complete_handoff_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let executable = std::env::var_os("CALCIFER_CODEX_COMPAT_BINARY")
            .map(PathBuf::from)
            .ok_or("CALCIFER_CODEX_COMPAT_BINARY must name the pinned Codex binary")?;

        let timeout = std::time::Duration::from_secs(180);
        let capability = verify_codex_handoff_compatibility_for_test(&executable, timeout)?;
        assert_eq!(capability.id(), "codex-handoff/0.144.4/v1");
        assert_eq!(capability.version(), "0.144.4");
        let cleanup_deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or("the direct compatibility cleanup deadline overflowed")?;
        capability
            .into_pinned_executable()
            .cleanup(cleanup_deadline)
            .map_err(|failure| failure.error())?;
        Ok(())
    }
}
