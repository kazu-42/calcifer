use crate::output::{Check, DoctorReport, Status};

pub(crate) fn inspect() -> DoctorReport {
    inspect_with(&PathExecutableLocator)
}

trait ExecutableLocator {
    fn is_available(&self, executable: &str) -> bool;
}

struct PathExecutableLocator;

impl ExecutableLocator for PathExecutableLocator {
    fn is_available(&self, executable: &str) -> bool {
        which::which(executable).is_ok()
    }
}

fn inspect_with(locator: &impl ExecutableLocator) -> DoctorReport {
    let host_supported = matches!(std::env::consts::OS, "linux" | "macos" | "windows");
    let host = if host_supported {
        Check::pass(
            "host",
            "supported",
            format!(
                "Detected supported host {}/{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        )
    } else {
        Check::warn(
            "host",
            "unsupported",
            format!(
                "Host {}/{} is not in the initial support matrix",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        )
    };

    let checks = vec![
        host,
        executable_check(locator, "codex_cli", "codex"),
        executable_check(locator, "claude_cli", "claude"),
        Check::pass(
            "manual_profile_selection",
            "implemented",
            "Explicit Codex profile registration, launch, and resume are available",
        ),
        Check::warn(
            "automatic_failover",
            "not_implemented",
            "Default-profile switching and automatic failover are not available in this preview",
        ),
    ];

    let status = if checks.iter().any(|check| check.status == Status::Fail) {
        Status::Fail
    } else if checks.iter().any(|check| check.status == Status::Warn) {
        Status::Warn
    } else {
        Status::Pass
    };

    DoctorReport::new(status, checks)
}

fn executable_check(
    locator: &impl ExecutableLocator,
    id: &'static str,
    executable: &'static str,
) -> Check {
    if locator.is_available(executable) {
        Check::pass(
            id,
            "found",
            format!(
                "An executable named '{executable}' was found on PATH; origin and compatibility were not verified"
            ),
        )
    } else {
        Check::warn(
            id,
            "not_found",
            format!("No executable named '{executable}' was found on PATH"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeLocator(&'static [&'static str]);

    impl ExecutableLocator for FakeLocator {
        fn is_available(&self, executable: &str) -> bool {
            self.0.contains(&executable)
        }
    }

    #[test]
    fn executable_checks_are_deterministic() {
        let both = inspect_with(&FakeLocator(&["codex", "claude"]));
        assert_check(&both, "codex_cli", Status::Pass, "found");
        assert_check(&both, "claude_cli", Status::Pass, "found");

        let codex_only = inspect_with(&FakeLocator(&["codex"]));
        assert_check(&codex_only, "codex_cli", Status::Pass, "found");
        assert_check(&codex_only, "claude_cli", Status::Warn, "not_found");

        let neither = inspect_with(&FakeLocator(&[]));
        assert_check(&neither, "codex_cli", Status::Warn, "not_found");
        assert_check(&neither, "claude_cli", Status::Warn, "not_found");
    }

    fn assert_check(report: &DoctorReport, id: &str, status: Status, code: &str) {
        let matching = report.checks().iter().find(|check| check.id() == id);
        assert!(
            matches!(matching, Some(check) if check.status() == status && check.code() == code),
            "missing expected check {id}/{code}"
        );
    }
}
