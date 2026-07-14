# Changelog

All notable changes to Calcifer will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will follow semantic versioning once the public CLI contract stabilizes.

## [Unreleased]

### Added

- Initial Rust CLI scaffold.
- Read-only `doctor` command with human and JSON output.
- OSS governance, security, architecture, and contribution documentation.
- Cross-platform CI and dependency update configuration.
- Unix managed Codex profile registration through the official `codex login` flow.
- Profile-pinned `run` and same-profile `resume` commands.
- Read-only per-profile Codex usage windows, reset times, workspace credits, spend controls, and rate-limit reset-credit status through the official app-server protocol.
- Stable JSON status output with redacted provider errors and display-only remaining percentages.
- Checked cold resume after wrapper restart by exact thread ID or official `--last` behavior.
- ADR for profile-independent conversation lineage and required cross-profile continuation after automatic failover.

### Security

- Managed directories and files are created with private Unix modes, profile metadata is atomically replaced, and profile mutation and child lifetime are protected by advisory locks.
- Reset-credit opaque IDs and provider display copy are excluded from Calcifer output.
- Displayed `0% remaining` is not treated as authoritative exhaustion because Codex rounds the upstream usage percentage.
- Managed auth/config are revalidated under an exclusive lease; account/provider-routing overrides are rejected and profile-local file storage is forced for both CLI and MCP OAuth credentials on every invocation.
- Login and status use a neutral managed cwd, provider JSONL input is bounded, and status probes receive a graceful shutdown window.
- A coordinator/provider-guardian pair uses split advisory leases so either side can survive a selective crash without exposing interactive lock FDs to provider background tools.
- Wrapper, coordinator, and guardian layers survive terminal cancellation signals until the official provider exits, including when that provider handles or ignores `SIGINT`.
- The bounded status app-server inherits only the provider-side lease, preventing a killed status parent from briefly admitting a second credential writer.
- Login, run, resume, and status now share one managed Codex command policy
  that strips ambient credentials, authentication/endpoint overrides,
  alternate config/state paths, cloud-task and remote-execution routes,
  connector/remote-auth tokens, test hooks, and implicit transcript/trace paths
  before the official provider starts; Unix coordinator and guardian helpers
  are sanitized before spawn as well.
- Interactive Codex launch now validates bounded repository-local configuration
  against a version-scoped safe-key policy at both coordinator and guardian
  boundaries, binds the provider to the inspected canonical cwd, and rejects
  child cwd, dynamic-feature, and non-UTF-8 argument bypasses before spawn.

### Known limitations

- Automatic account failover and the accepted cross-profile conversation handoff design are not implemented.
- Managed profile registration is disabled on Windows until current-user-only ACL creation is verified.
- `resume` restores persisted Codex conversation state; it does not restart an in-flight tool call or replay a prompt.
- Exact previous-thread auto-selection, active-profile monitoring, and provider account-identity verification are not implemented; current status reads idle local profiles, which may alias the same underlying account.
