# Roadmap

Calcifer is being built in narrow, reviewable slices. Dates are intentionally omitted until the security contracts and provider-supported signals are validated.

## Phase 0: OSS bootstrap

- [x] Buildable Rust CLI
- [x] Read-only human and JSON `doctor` output
- [x] Linux, macOS, Windows, formatting, Clippy, and MSRV CI
- [x] Architecture, security, contribution, and disclosure documentation
- [ ] First signed pre-release binary

## Phase 1: secure local registry

- [ ] Cross-platform data-directory selection with explicit override
- [ ] Opaque profile IDs and normalized display-name validation
- [ ] Managed-root ownership marker and safe deletion boundary
- [ ] Unix `0700`/`0600`, Windows current-user-only ACLs, symlink/owner checks, and atomic metadata writes
- [ ] OS advisory locks and deterministic lock ordering
- [ ] Redaction and crash-injection test harnesses

## Phase 2: Codex profile isolation

- [ ] `auth add/list/show/remove/reauth codex`
- [ ] Official `codex login` in a profile-specific `CODEX_HOME`
- [ ] Provider identity verification before profile publication
- [ ] File-backed credential-store configuration scoped to the managed home
- [ ] Adapter-selected, validated official executable with exact argv, arbitrary-command rejection, signal, PTY, and exit-code behavior
- [ ] No writes to the user's global `~/.codex`
- [ ] Same-profile lifetime lease; different profiles may run concurrently

## Phase 3: usage observations

- [ ] Identify a documented or official structured Codex usage signal
- [ ] Version-gated parser with `available | exhausted | unknown` classification
- [ ] Timestamped source and reset metadata
- [ ] Staleness, provider failure, auth failure, and unknown-format tests
- [ ] Human and stable JSON status commands

Calcifer will not ship automatic failover by scraping an unstable human string and treating parse failures as zero.

## Phase 4: explicit failover pools

- [ ] User-level, provider-specific, same-trust-domain pool configuration
- [ ] Default-off behavior and explicit per-invocation pin
- [ ] Bounded one-pass selection with cooldown
- [ ] Identity and fresh usage revalidation inside the candidate profile lease
- [ ] Visible local profile, provider, trust-domain, and selection-reason notice before launch
- [ ] No mid-session credential swap
- [ ] No automatic command or prompt replay
- [ ] Audit events containing no secret or stable account identifier

## Phase 5: Claude support

- [ ] Revalidate Anthropic's current public documentation and policy
- [ ] Use officially supported setup-token or credential-store surfaces and fail closed without an OS credential store
- [ ] Sanitize conflicting Claude authentication environment variables
- [ ] Keep regular subscription OAuth replication out of scope unless Anthropic provides a stable, permitted integration contract
- [ ] Treat macOS, Linux, and Windows credential behavior as separate compatibility lanes

## Release gates

A functional `0.1.0` requires:

- the Codex isolation slice working on supported platforms;
- no global credential mutation;
- security tests for paths, permissions, identity, locking, redaction, and process behavior;
- a reviewed recovery path for interrupted add/remove/reauth operations;
- current provider documentation and terms read-back;
- checksummed release artifacts and a documented rollback/uninstall path.
