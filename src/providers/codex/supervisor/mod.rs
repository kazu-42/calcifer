//! Default-unused process authority for staged supervised Codex sessions.

mod authority;
mod channel;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod coordinator;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod coordinator_terminal;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod entry;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod fixture;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod guardian;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod launcher;
#[cfg(all(
    test,
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod packaged_smoke;
mod process;
mod protocol;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod provider;
mod runtime;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod session;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod signals;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod startup;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod terminal;
mod transfer;

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) use fixture::run_internal_fixture;

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) fn internal_tui_launcher_requested() -> bool {
    launcher::internal_launcher_requested()
}

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) fn run_internal_tui_launcher() -> std::process::ExitCode {
    match launcher::run_exec_launcher() {
        Ok(code) => code,
        Err(_) => std::process::ExitCode::from(70),
    }
}

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) fn internal_production_role_requested() -> bool {
    entry::internal_production_role_requested()
}

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) fn run_internal_production_role() -> std::process::ExitCode {
    entry::run_internal_production_role()
}

#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(in crate::providers::codex) use provider::ProviderLaunchAuthorization;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
pub(in crate::providers::codex) use provider::{ConnectedMonitorSession, MonitorSessionCapability};
