//! Fail-closed compatibility gate for cross-profile Codex thread handoff.

use serde_json::Value;

const JSON_SCHEMA_DRAFT_07: &str = "http://json-schema.org/draft-07/schema#";
const PROTOCOL_SCHEMA_TITLE: &str = "CodexAppServerProtocolV2";
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

#[allow(dead_code)] // The runtime gate consumes this projection later in issue #28.
fn validate_handoff_schema_pair(
    default_schema: &Value,
    experimental_schema: &Value,
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

    Ok(HandoffSchemaContract { _private: () })
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
        || property(definition, "thread")
            != Some(&serde_json::json!({ "$ref": "#/definitions/Thread" }))
    {
        return Err(HandoffSchemaError::Malformed);
    }
    Ok(())
}

fn validate_thread(schema: &Value) -> Result<(), HandoffSchemaError> {
    let definition = definition(schema, "Thread")?;
    if definition.get("title").and_then(Value::as_str) != Some("Thread")
        || definition.get("type").and_then(Value::as_str) != Some("object")
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
    use serde_json::{Value, json};

    use super::*;

    fn schema_pair() -> (Value, Value) {
        let thread = json!({
            "title": "Thread",
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

    #[test]
    fn accepts_the_exact_v0_144_4_handoff_projection() {
        let (default_schema, experimental_schema) = schema_pair();

        assert_eq!(
            validate_handoff_schema_pair(&default_schema, &experimental_schema),
            Ok(HandoffSchemaContract { _private: () })
        );
    }

    #[test]
    fn rejects_a_default_schema_that_authorizes_fork_by_path() {
        let (mut default_schema, experimental_schema) = schema_pair();
        default_schema["definitions"]["ThreadForkParams"]["properties"]["path"] =
            experimental_schema["definitions"]["ThreadForkParams"]["properties"]["path"].clone();

        assert_eq!(
            validate_handoff_schema_pair(&default_schema, &experimental_schema),
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
                validate_handoff_schema_pair(&default_schema, &experimental_schema),
                Err(HandoffSchemaError::Malformed)
            );
        }
    }

    #[test]
    fn rejects_malformed_fork_resume_and_thread_response_projections() {
        for pointer in [
            "/definitions/ThreadForkResponse/properties/thread",
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
                validate_handoff_schema_pair(&default_schema, &experimental_schema),
                Err(HandoffSchemaError::Malformed),
                "mutation at {pointer} must fail closed"
            );
        }
    }
}
