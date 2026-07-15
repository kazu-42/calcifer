# Roadmap

Calcifer is being built in narrow, reviewable slices. Dates are intentionally omitted until the security contracts and provider-supported signals are validated.

## Phase 0: OSS bootstrap

- [x] Buildable Rust CLI
- [x] Read-only human and JSON `doctor` output
- [x] Linux, macOS, Windows, formatting, Clippy, and MSRV CI
- [x] Architecture, security, contribution, and disclosure documentation
- [ ] First checksummed and provenance-attested pre-release binary
- [x] Credential-free strict-channel update check for immutable manifest-v1 releases

## Phase 1: secure local registry

- [x] Platform data-directory selection with absolute `CALCIFER_HOME` override
- [x] Opaque profile IDs and normalized display-name validation
- [x] Per-profile ownership marker and staging cleanup boundary
- [x] Unix `0700`/`0600`, symlink/type checks, and atomic registry writes
- [ ] Windows current-user-only ACL creation and validation
- [ ] Owner-UID checks and hardened directory-relative filesystem operations (implemented for destructive profile removal; remaining storage paths still require migration)
- [x] OS advisory locks for the current single-profile operations
- [ ] Deterministic multi-profile/session lock ordering
- [ ] Redaction and crash-injection test harnesses

## Phase 2: Codex profile isolation

- [ ] Complete `auth add/list/show/rename/remove/reauth codex` (`add`, `list`, atomic alias-only `rename`, and confirmed crash-safe local `remove` are implemented)
- [x] Keep profile registry schema v1 rollback-compatible while using a bounded transient removal barrier, fail-closed mount proof, and immutable-ID lineage during local deletion
- [x] Official `codex login` in a profile-specific `CODEX_HOME`
- [x] Version-scoped private provider identity verification before profile publication
- [x] Explicit identity verification for legacy profiles; unbound profiles remain manual-only
- [x] File-backed credential-store configuration scoped to the managed home
- [x] Revalidate managed auth/config and reject account/provider-routing argument overrides
- [ ] Complete adapter-selected executable hardening and process supervision (direct argv, owner/parent-mode checks, crash-tolerant split launch leases, and ordinary exit codes are implemented; complete signal semantics remain)
- [x] No writes to the user's global `~/.codex`
- [x] Same-profile lifetime lease; different profiles may run concurrently
- [x] Same-profile `resume` by exact thread ID or official `--last`
- [x] Automatic same-profile `{profile_id, cwd, thread_id}` capture, crash reconciliation, and exact cold restore
- [x] Explicit fail-closed `--untracked` escape hatch with durable manual-recovery state

## Phase 3: usage observations

- [x] Use official structured `account/rateLimits/read`; do not scrape TUI text
- [x] Explicit supported-version/initialize-home/usage-schema gate for on-demand status
- [x] `available | exhausted | unknown` classification without treating rounded 100% as exhaustion
- [x] Timestamped source, window reset metadata, spend control, and reset-credit count/expiry
- [x] Provider failure, auth failure, timeout, missing-field, and unknown-format handling
- [x] Human and stable JSON status commands for one or all idle profiles
- [ ] Profile-owned supervisor or safe observation cache for active-session monitoring
- [ ] Snapshot cache, staleness state, TTL/backoff, and notification merge

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
- [ ] Continue the same logical conversation after confirmed exhaustion by advancing its profile-local thread generation

## Phase 4.5: required conversation handoff

- [x] Decide that successful automatic failover continues the same user-visible conversation; see [ADR 0001](adr/0001-cross-profile-conversation-handoff.md)
- [ ] Model one logical conversation as a lineage of profile-local provider threads
- [ ] Bind every lineage generation to profile, canonical cwd, trust domain, thread ID, and exact rollout path
- [x] Version-gate Codex's experimental `thread/fork.path` field and remote TUI contract with `codex app-server generate-json-schema --experimental --out <dir>` drift checks plus a synthetic runtime smoke test
- [x] Extract a bounded, observe-only readiness relay with separate synthetic-fork and exact-resume policies; keep it internal and opaque after readiness (issue #48 and [ADR 0003](adr/0003-supervised-codex-session.md))
- [x] Prove the default-unused coordinator/guardian authority, bounded lifecycle channel, guardian-direct fake process groups, exact reap, worker join, private runtime cleanup, descriptor non-inheritance, and retained-A crash behavior (issue #50)
- [ ] Integrate the real guardian-owned App Server/TUI lifecycle, persistent typed monitor, PTY input gate, signals, and terminal disposition protocol from ADR 0003
- [ ] Canonical containment, hard-link/symlink/owner/mode validation, serialized handoff, and complete source-to-target integration
- [x] Linux/macOS no-gap verified target reservation and one-shot guardian provider-lease transfer; internal and unused until supervised handoff integration
- [ ] Stop and reap the old TUI and App Server before reading its rollout under the target profile
- [ ] Preserve source effective settings while keeping authentication/provider routing target-profile-owned
- [ ] Materialize a new target-profile rollout, atomically commit the generation, and reconcile non-idempotent fork crash ambiguity
- [ ] Keep the monitor event-only and require the official TUI before accepting a new turn
- [ ] Restore transcript only; never replay an interrupted turn

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
