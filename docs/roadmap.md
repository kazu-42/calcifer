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
- [ ] Expose active-session monitoring through a public profile-owned supervisor or safe observation cache (the #54 typed monitor is internal and default-unused)
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
- [x] Add the pinned real guardian-owned App Server/TUI lifecycle, persistent typed monitor, PTY input gate, signals, persistent shell anchor, completion protocol, and fail-closed terminal disposition behind a default-unused same-profile entrypoint. This records implementation presence only; #54 acceptance still depends on the following recovery and package gates (issue #54 and [ADR 0003](adr/0003-supervised-codex-session.md))
- [ ] Run and pass the non-ignored credential-free deterministic recovery fixture at all seven closed production checkpoints: startup queued, ready, active, suspended, retained quiescing, retained restore pending, and retained cleanup pending. The checkpoint must remain observation-only until the sole generation-bound `CFRCR` request; the first four cases expect failed-clean with zero inference calls and the retained three expect completed-clean with exactly one validated loopback call. Every case must pass the same four independent deletion proofs; the fourth namespace proof additionally requires the identity-checked private compatibility stage parent to be empty. The sealed `cfg(test)` compatibility seam and strict owner-private provider wrapper are recovery-phase evidence, not official Codex compatibility evidence
- [ ] Run and pass the checksum-pinned official `0.144.4` `official-tui-normal` and `official-tui-recovery` scenarios on this exact tree and in their independent Linux/macOS matrix jobs. Both are designed to exercise the production coordinator/guardian session and shared guardian-bootstrap core through bounded package-only seams, pass the completion endpoint across real package-parent-to-coordinator and coordinator-to-guardian `exec` boundaries, and check the provider-release-only `CFCMP\x01\r\n` frame plus EOF at the parent. `CFCMP` is not owner, session, or shell success by itself. The test-only dispatcher bypasses the production `CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE` dispatcher/parser and persistent shell-anchor role, so these scenarios make no parser coverage claim. One aggregate gate must require `contracts`, `official-tui-normal`, and `official-tui-recovery`
- [ ] Evaluate platform-owned containment for escaped `setsid(2)` descendants separately in issue #56. Until then, keep issue #55's zero-residue claim limited to Calcifer-owned direct children and known process groups plus identity-checked runtime, FD, and socket evidence
- [ ] Wire that internal supervisor into public run/resume and the cross-profile transition transaction; keep selection, journaling, target fork, and cross-profile transition recovery disabled until their proofs are complete
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
