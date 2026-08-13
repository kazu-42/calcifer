//! Read-only adapters for official provider CLIs.

#[cfg(any(test, target_os = "linux"))]
pub mod claude;
pub mod codex;
