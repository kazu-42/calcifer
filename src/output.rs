use serde::Serialize;

const SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Check {
    id: &'static str,
    pub(crate) status: Status,
    code: &'static str,
    message: String,
}

impl Check {
    pub(crate) fn pass(id: &'static str, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            id,
            status: Status::Pass,
            code,
            message: message.into(),
        }
    }

    pub(crate) fn warn(id: &'static str, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            id,
            status: Status::Warn,
            code,
            message: message.into(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn id(&self) -> &'static str {
        self.id
    }

    #[cfg(test)]
    pub(crate) const fn status(&self) -> Status {
        self.status
    }

    #[cfg(test)]
    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct DoctorReport {
    schema_version: u8,
    command: &'static str,
    calcifer_version: &'static str,
    ok: bool,
    status: Status,
    checks: Vec<Check>,
}

impl DoctorReport {
    pub(crate) fn new(status: Status, checks: Vec<Check>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command: "doctor",
            calcifer_version: env!("CARGO_PKG_VERSION"),
            ok: status != Status::Fail,
            status,
            checks,
        }
    }

    pub(crate) fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    pub(crate) fn to_human(&self) -> String {
        let mut lines = vec![format!("Calcifer {} (pre-alpha)", self.calcifer_version)];
        for check in &self.checks {
            lines.push(format!(
                "[{status}] {id}: {message}",
                status = check.status.label(),
                id = check.id,
                message = check.message
            ));
        }
        lines.push("No credentials were read or changed.".to_owned());
        lines.join("\n")
    }

    pub(crate) const fn exit_code(&self) -> u8 {
        if self.ok { 0 } else { 1 }
    }

    #[cfg(test)]
    pub(crate) fn checks(&self) -> &[Check] {
        &self.checks
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorReport {
    schema_version: u8,
    command: Option<&'static str>,
    ok: bool,
    error: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

impl ErrorReport {
    pub(crate) const fn usage() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command: None,
            ok: false,
            error: ErrorBody {
                code: "usage_error",
                message: "Invalid command-line arguments. Run calcifer --help.",
            },
        }
    }

    pub(crate) fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_report_requests_failure_exit_code() {
        let report = DoctorReport::new(Status::Fail, Vec::new());
        assert_eq!(report.exit_code(), 1);
    }
}
