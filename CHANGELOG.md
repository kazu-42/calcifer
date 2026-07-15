# Changelog

All notable changes to Calcifer will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will follow semantic versioning once the public CLI contract stabilizes.

## [Unreleased]

### Added

- Crash-safe same-profile Codex thread capture and bare `calcifer resume`, which
  validates the tracked workspace head and invokes exact official CLI resume
  without replaying a prompt.
- Conservative rollout-store completeness and change fingerprints for the
  hidden Codex 0.144.4 filesystem scan cap and same-second thread updates.
- Explicit `run --untracked` and profile-specific `resume --untracked` modes
  that durably disable automatic workspace resume before skipping capture and
  retain cross-profile-safe in-flight ownership until the provider exits.
- Version-scoped private Codex provider-identity binding during registration and
  explicit `calcifer auth verify codex@<alias>` migration for legacy profiles.
- Versioned deterministic release manifests with archive and in-archive binary
  digests for all five supported native targets.
- Draft-staged immutable releases with a read-first maintainer-local publisher
  that binds the single publication write to an exact numeric release ID.
- Offline, atomic `auth rename` for changing a local profile alias without
  changing its immutable ID, managed home, authentication, provider identity,
  or conversation state, with stable human/JSON output and commit-uncertain
  read-back guidance.
- Credential-free `calcifer update check` with strict stable/preview SemVer
  channels, exact compile-target selection, stable JSON v1 output, and bounded
  immutable manifest/checksum verification.

### Changed

- Exact previous-thread auto-selection is now available for supported Codex
  versions; active-profile monitoring and automatic failover remain future
  work.
- Unix startup now applies umask `0077` before any managed state or provider
  child is created, while owner-safe legacy `0755`/`0644` nested rollouts remain
  readable behind the private managed-home boundary.

### Fixed

- Bare and explicit exact resume preserve persisted interrupted or unknown-crash
  state through pre-launch validation, including behind pending or
  needs-selection workspace state. Terminal profile/cwd ownership conflicts no
  longer leave an unrecoverable pending launch in an infinite retry loop.

### Security

- An installation-local HMAC key and profile-private identity markers reject
  duplicate aliases for the same effective ChatGPT account/workspace scope.
  Raw provider identifiers, fingerprints, and local key IDs remain outside the
  registry and all human/JSON diagnostics; key loss and credential drift fail
  closed for identity-dependent selection.
- Release publication now revalidates bounded archive bodies, canonical
  manifest semantics, artifact-attested raw and peeled source-tag identity,
  no-bypass repository controls, assembled-asset attestations, and the
  immutable release attestation before reporting success.
- Documented coordinated vulnerability disclosure, including patched-release
  ordering, urgent-notification exceptions, and audited emergency release
  removal under the no-bypass release-tag ruleset.
- Update checks send no authorization or ambient token data, follow only bounded
  allowlisted HTTPS redirects, reject mutable or malformed releases, and never
  substitute another target ABI or claim an un-downloaded archive was verified.

## [0.1.0-alpha.3] - 2026-07-15

### Added

- Initial Rust CLI scaffold.
- Read-only `doctor` command with human and JSON output.
- OSS governance, security, architecture, and contribution documentation.
- Cross-platform CI and dependency update configuration.
- Unix managed Codex profile registration through the official `codex login` flow.
- Profile-pinned `run` and same-profile `resume` commands.
- Read-only per-profile Codex usage windows, reset times, workspace credits, spend controls, and rate-limit reset-credit status through the official app-server protocol.
- Stable JSON status output with redacted provider errors and display-only remaining percentages.
- Fail-closed Codex `0.144.4` status compatibility gate with canonical managed-home verification and explicit human/JSON compatibility metadata.
- Checked cold resume after wrapper restart by exact thread ID or official `--last` behavior.
- ADR for profile-independent conversation lineage and required cross-profile continuation after automatic failover.
- Native five-target release packaging with deterministic archive metadata,
  checksums, provenance attestations, dry-run validation, and a maintainer
  release/rollback runbook.

### Fixed

- Official Codex project-trust updates no longer make a managed profile unusable
  on its next status, run, or resume operation. Managed configuration is now
  checked by a bounded Codex-version-scoped semantic policy instead of complete
  byte equality, and MCP OAuth credentials are forced into the selected
  profile's file store rather than an implicit shared keyring.

### Security

- Managed directories and files are created with private Unix modes, profile metadata is atomically replaced, and profile mutation and child lifetime are protected by advisory locks.
- Reset-credit opaque IDs and provider display copy are excluded from Calcifer output.
- Displayed `0% remaining` is not treated as authoritative exhaustion because Codex rounds the upstream usage percentage.
- Managed auth/config are revalidated under an exclusive lease; valid
  provider-owned project trust is accepted, while unknown and
  account/provider/state/dynamic-extension settings are rejected and
  profile-local file storage is forced for both CLI and MCP OAuth credentials
  on every invocation.
- Managed profiles cannot replace the pinned project-root discovery markers, so
  Calcifer and Codex evaluate the same repository configuration boundary.
- Managed profiles reject top-level role definitions and every auto-discovered
  `CODEX_HOME/agents` filesystem node before registry publication or provider
  spawn, preventing indirect role files from importing unvalidated complete
  configuration layers.
- Managed profiles reject MCP OAuth callback URL and port overrides so connector
  authorization cannot be redirected outside the reviewed endpoint route.
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
- Every repository `.codex/agents` filesystem node now fails closed before
  provider spawn, including when the sibling `config.toml` is absent, preventing
  auto-discovered role files from importing a complete provider-routing layer.
- Untested or malformed App Server initialize contracts stop before the usage
  request; unsupported, unverified, authentication, timeout, and protocol
  failures remain `unknown` and cannot authorize failover.

### Known limitations

- Automatic account failover and the accepted cross-profile conversation handoff design are not implemented.
- Managed profile registration is disabled on Windows until current-user-only ACL creation is verified.
- `resume` restores persisted Codex conversation state; it does not restart an in-flight tool call or replay a prompt.
- Exact previous-thread auto-selection, active-profile monitoring, and provider account-identity verification are not implemented; current status reads idle local profiles, which may alias the same underlying account.

[Unreleased]: https://github.com/kazu-42/calcifer/compare/v0.1.0-alpha.3...HEAD
[0.1.0-alpha.3]: https://github.com/kazu-42/calcifer/releases/tag/v0.1.0-alpha.3
