//! Default-unused process authority for staged supervised Codex sessions.

mod authority;
mod channel;
#[cfg(feature = "internal-supervisor-fixture")]
mod fixture;
mod process;
mod protocol;
mod runtime;
mod transfer;

#[cfg(feature = "internal-supervisor-fixture")]
pub(crate) use fixture::run_internal_fixture;
