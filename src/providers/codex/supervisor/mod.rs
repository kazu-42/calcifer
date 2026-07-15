//! Default-unused process authority for staged supervised Codex sessions.

mod authority;
mod channel;
#[cfg(all(
    feature = "internal-supervisor-fixture",
    any(target_os = "linux", target_os = "macos")
))]
mod fixture;
mod process;
mod protocol;
mod runtime;
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
