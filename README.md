# Calcifer

[![CI](https://github.com/kazu-42/calcifer/actions/workflows/ci.yml/badge.svg)](https://github.com/kazu-42/calcifer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

Calcifer is a pre-alpha, local-first Rust wrapper for running official coding-agent CLIs with isolated account profiles and structured usage visibility.

> [!WARNING]
> **Status: functional pre-alpha.** Codex profile registration with private provider-identity deduplication, confirmed crash-safe local removal, pinned launches, same-profile resume, and on-demand usage status are implemented on Unix. A pinned, default-unused Linux/macOS supervisor implementation is present internally, but its cross-platform acceptance evidence is incomplete. On 2026-07-20, the final Issue #54 candidate source passed two consecutive checksum-pinned Codex 0.144.4 normal-session runs (145.61 s and 144.97 s), one retained-cleanup recovery run (170.60 s), and three consecutive deterministic seven-checkpoint recovery runs (11.54 s, 11.21 s, and 11.50 s) on Apple silicon. The required Ubuntu 24.04 and macOS CI matrix runs remain pending. The official scenarios exercise the real App Server and remote TUI through the coordinator, guardian, provider session, PTY, and job-control implementations under a test-owned terminal harness. Their guardian helper enters the shared production guardian-bootstrap core through bounded package-only seams, and their completion endpoint crosses real package-parent-to-coordinator and coordinator-to-guardian `exec` boundaries before the parent checks the provider-release-gated exact record and EOF. The test-only role dispatcher does not execute the production `CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE` dispatcher/parser or persistent shell-anchor role, so these scenarios make no parser coverage claim. No public supervised command uses this path. Automatic failover, cross-profile session handoff, reauthentication, and verified Windows credential ACLs are not implemented yet.

Calcifer is intended to make routine selection among accounts that you already own or are authorized to use feel boring: authenticate each profile through the provider's official CLI, keep each profile isolated, and start every new CLI process with an explicit profile.

Calcifer does **not** bypass rate limits, create quota, automate account creation, share credentials, or remove provider login requirements. Initial login and re-authentication may still open a browser.

## Why

Logging out of a coding-agent CLI just to select another authorized account can invalidate unrelated sessions or disturb global browser state. A local wrapper can avoid that global mutation by giving each profile its own provider-specific home and always launching the official CLI inside that isolated environment.

```text
official CLI login
        |
        v
profile-specific local credential home
        |
        v
Calcifer selects one immutable profile for a new process
        |
        v
official CLI owns authentication and token refresh
```

A running process keeps the profile it started with. Switching affects newly started processes only.

## What works today

The first functional slice manages isolated Codex homes on macOS and Linux:

```console
# Browser authentication is handled by the official Codex CLI.
calcifer auth add codex work
calcifer auth add codex personal
calcifer auth list

# Bind a profile created by an earlier Calcifer release without logging in again.
calcifer auth verify codex@work

# Change only a local display alias; no browser or provider process is used.
calcifer auth rename codex@work client-a

# Remove one local managed profile after a TTY confirmation, or explicitly.
calcifer auth remove codex@client-a
calcifer auth remove codex@client-a --yes
calcifer --json auth remove codex@client-a --yes

# Read every idle registered profile, or one idle profile, without changing the global login.
calcifer status
calcifer status codex@work
calcifer --json status

# Check this binary's release channel, or select one explicitly.
calcifer update check
calcifer update check --channel stable
calcifer --json update check --channel preview

# Start Codex in one immutable profile.
calcifer run codex@work
calcifer run codex@personal -- --no-alt-screen

# Explicitly skip conversation capture when manual recovery is acceptable.
calcifer run --untracked codex@work
calcifer resume --untracked codex@work

# Reopen the newest session in a profile, pin an exact thread, or restore this workspace head.
calcifer resume codex@work
calcifer resume codex@work 01900000-0000-7000-8000-000000000001
calcifer resume
```

Each registration gets a private, opaque directory and a complete profile-specific `CODEX_HOME`. The official CLI writes authentication, project trust, and session state there, so exiting Calcifer does not discard the conversation. Before publication, Calcifer version-gates the installed Codex `0.144.4` adapter and derives an installation-private HMAC fingerprint from the effective ChatGPT account/workspace scope in the provider-owned credential file. A second local alias for the same scope is rejected without displaying or storing the raw scope outside `auth.json`; different scopes are not claimed to guarantee independent provider quota. Profiles created by earlier releases remain usable for explicit operations and become failover-eligible only after an explicit, non-interactive `auth verify` succeeds. Calcifer accepts supported Codex project-trust updates semantically while continuing to require profile-local file storage for both Codex account and MCP OAuth credentials and reject profile/provider routing overrides, including MCP OAuth callback URL and port overrides. Managed Codex role configuration is currently unsupported: both a top-level `agents` table and any auto-discovered `CODEX_HOME/agents` node fail closed because role files can add indirect complete configuration layers. `calcifer resume codex@work` remains the explicit official `codex resume --last` convenience; bare `calcifer resume` resolves Calcifer's exact tracked workspace thread and never falls back to `--last`.

Profile aliases are mutable local display metadata. `auth rename` atomically
changes only the alias in Calcifer's private registry while holding the same
profile lease used by run, resume, and status. The opaque profile ID, managed
directory, `CODEX_HOME`, authentication, provider-identity marker, and session
state remain unchanged. Rename is offline: it neither resolves nor starts the
provider executable, opens a browser, refreshes a token, nor contacts a
network service. If registry durability becomes uncertain after its atomic
visibility point, Calcifer reports `registry_commit_uncertain`; read back
`auth list` instead of retrying blindly.

`auth remove` is also entirely local and offline. Without `--yes`, it requires
stdin to be a TTY, displays the local profile ID and deletion scope, and accepts
only an explicit `yes`. Non-TTY use without `--yes` and JSON use without
`--yes` fail before reading or changing managed state. Removal acquires both
profile lifetime leases, so an active run, resume, status probe, verification,
or reauthentication operation returns `profile_busy` without preparing a
deletion.

After confirmation, Calcifer validates the exact ownership-marked profile tree,
then atomically replaces the stable schema-v1 `profiles.json` with a bounded,
self-contained transient schema-v2 removal barrier. The barrier embeds the
expected v1 registry and a path-free tree-manifest proof; it is the first
durable transaction state and makes published alpha.4 binaries fail closed
instead of writing through an in-progress deletion. Calcifer next persists a
matching private sidecar, renames the UUID directory to a same-filesystem opaque
tombstone, and atomically publishes a normal schema-v1 registry without the
immutable ID. That final registry update is the deletion visibility point:
only after readback proves the ID is absent does Calcifer unlink the tombstone
through constrained directory descriptors.

The next profile-registry operation, including `auth list`, recovers an
unambiguous interruption to either the manifest-complete old state before
visibility or the complete removed state afterward. Completed state remains
schema-v1 and readable by alpha.4. Ambiguous or mismatched barriers and
sidecars, replaced or missing registries and roots, traversable or replaced
directories, hard-linked regular files, unexpected owners, group/other-writable
directories or regular files, mount crossings, and malformed tombstones fail
closed without recursive deletion. On macOS, every removal-tree entry must be
free of extended ACL entries, and managed directories and regular files must
also have supported file flags. Calcifer resolves the deepest existing prefix
of its configured Unix storage root to a physical path once, stores that path,
and passes it unchanged to coordinator and guardian helpers. Later managed
operations reject every symlink ancestor and require each real ancestor to be
root/current-user-owned and non-replaceable by ordinary mode checks. On macOS,
Calcifer binds type, owner, mode, flags, ACL, and inode identity for each
acceptance decision to one no-follow descriptor and compares it with the
visible pathname. It rejects a parent ACL that could grant, inherit, or block
child deletion, and rejects append, immutable, XNU-inherited, and unknown
parent flags. A new private file is cleared and read back through the same open
descriptor as ACL-free and safely flagged before credential bytes are written.
An already ACL-authorized different OS principal that actively mutates the
namespace during or after validation remains outside the guarantee because the
official Codex CLI accepts `CODEX_HOME` only as a pathname. On
Linux, removal and its recovery require kernel 5.8 or newer
so `statx` mount IDs and `openat2` constraints are both available; Calcifer never
falls back to `st_dev` or an unconstrained `openat`. macOS compares
descriptor-derived `fstatfs` mount identities. Mount identity tokens remain
ephemeral in memory and are never persisted or logged.

Provider-created symlinks, Unix sockets, FIFOs, and other non-directory leaves
are recorded in the manifest but never opened or traversed. Cleanup unlinks
only their names relative to an already constrained parent directory, so an
absolute or dangling symlink target remains untouched. Regular files must be
single-link, and every traversed directory must remain owner-readable,
owner-writable, and owner-searchable; ambiguous replacements still fail closed.
The ownership marker and lifetime-lock names are control-plane state, not
provider leaves, and must remain private single-link regular files: replacing
either with a symlink or hard link always blocks removal before a transaction is
prepared. Managed lock files and the removal sidecar are opened with no-follow
semantics and their opened descriptors are matched to the visible inode before
any lock, read, or durability operation.

Removal does not start Codex, open a browser, contact a provider endpoint,
revoke tokens, change global `~/.codex`, delete conversation lineage metadata,
or remove Calcifer's installation identity key. Reusing the old alias creates a
fresh profile UUID; an existing conversation remains bound to the now-missing
old UUID and cannot silently move to the replacement account. Local unlinking
is not guaranteed secure erasure from backups, snapshots, journaled
filesystems, or SSD wear leveling. Use the provider's revocation controls when
credential invalidation is required.

Before interactive `run` and `resume`, Calcifer canonicalizes the working directory and checks every repository-local `.codex` layer from the nearest real `.git` root to that directory. Any `.codex/agents` filesystem node fails closed even when `config.toml` is absent; otherwise only a Codex 0.144.4-scoped set of repository settings that do not own managed authentication, provider routing, dynamic features, or state locations is accepted. Unknown keys, ambiguous filesystem nodes, invalid TOML, and files larger than 1 MiB fail before Codex starts. In a linked worktree, Codex 0.144.4 can additionally merge only `hooks` from the primary checkout; Calcifer does not resolve that external hook source, and repository hooks remain outside its sandbox guarantee. This preflight protects Calcifer's account-routing boundary, but it does not make repository hooks, plugins, tools, or code safe.

Account-only operations do not need repository context. `auth add` and `status`
therefore run the official CLI from a private runtime directory with its own
`.git` boundary, while retaining the selected profile-specific `CODEX_HOME`.
This remains isolated even when `CALCIFER_HOME` itself is stored inside a Git
repository with local Codex configuration.

For supported Codex 0.144.4 sessions, Calcifer captures the immutable `{profile ID, canonical cwd, thread ID}` binding in a separate private `conversations.json`. Bare `calcifer resume` validates that exact rollout under its source-profile lease and invokes `codex resume <exact-uuid>` without a prompt. A clean wrapper restart therefore restores the tracked history without an account selector or thread lookup. Interrupted and uncertain crash boundaries show a warning before reopening; missing, archived, incompatible, cross-profile, cross-cwd, corrupt, or ambiguous state stops before provider launch. Resume restores persisted history, not a dead process or in-flight tool call, and never resends the last prompt, approval answer, command, or tool call.

Normal `run` and profile-specific `resume` remain fail-closed when Calcifer cannot prove a complete capture inventory. `--untracked` is the explicit manual escape hatch for `run` or profile-specific `resume --last`: it performs no App Server inventory, refuses an unresolved pending launch in the workspace, durably marks the workspace as requiring selection before spawning Codex, retains a metadata-only in-flight ownership record until the official child exits, and prints a warning. That ownership prevents a concurrent exact resume under another profile from restoring a stale automatic head; an exact process that started first also cannot refresh over a later untracked marker. Bare `calcifer resume` remains disabled afterward until `calcifer resume codex@<alias> <exact-thread-id>` validates and restores a tracked head. The flag cannot be combined with an exact thread ID or bare resume; a provider argument named `--untracked` must follow the `--` separator as usual.

`status` starts the installed official `codex app-server` inside each idle profile and calls the structured `account/rateLimits/read` method. Before that read, it requires the tested Codex `0.144.4` initialize contract and verifies that the server reports the selected canonical `CODEX_HOME`. Untested versions, changed initialize data, a different home, or a changed usage schema fail closed as `unknown`; Calcifer does not send the usage request after an initialize-gate rejection. It displays all returned limit buckets, primary and secondary used/remaining percentages, reset times, workspace credit state, monthly spend control when present, and rate-limit reset-credit count and expirations. It does not scrape the interactive `/status` screen or read token values from `auth.json`.

An active `run` or `resume` holds a split exclusive lease because a second Codex process could race credential refresh and session writes. A launch coordinator owns one half and a provider guardian owns the other; either process surviving a selective crash keeps the profile busy until the exact provider exits. Consequently, status for that active profile is currently `profile_busy` / `unknown`; a list query inspects profiles serially with a per-profile timeout. Active-session monitoring, cached last-known observations, and automatic failover still require a profile-owned usage supervisor. Provider identity is revalidated under the same exclusive lease before any future automatic selection; a changed or externally replaced login fails closed instead of silently rebinding the local alias.

An internal Linux/macOS primitive can now reserve a revalidated target and
split its lifetime lease with a guardian without an unlock/reacquire gap. It is
not connected to a public command yet; current `run`, `resume`, `status`, and
persisted schemas are unchanged.

Issue #54 also connects the previously synthetic process/PTY kernel to the
pinned Codex `0.144.4` App Server, typed monitor, readiness relay, and official
remote TUI behind an internal, default-unused entrypoint. The coordinator holds
lease A, the guardian holds lease B, and App Server, TUI, shell tools, and
unrelated children inherit neither lease nor supervisor control descriptors.
The persistent shell-facing anchor accepts only one exact eight-byte terminal
record followed by EOF. `CFCMP\x01\r\n` carries provider-release proof only: it
is never owner, session, anchor, or shell success by itself, and cannot release
an owner without the independently required exact waits and exact frame-plus-EOF
checks. The guardian cannot publish it until it consumes a move-only proof that
the App Server never started or that its exact direct child was sent the one
allowed `SIGTERM` and then exited with code zero. The distinct versioned
`CFRET\x01\r\n` record carries no reason, identity, or provider data and means
only that the guardian has reached an unrecoverable retained boundary. Exact
record plus kernel EOF makes the anchor retain its direct child, immutable tty
snapshot, and completion endpoint and park; it is never a nonzero or successful
shell disposition.
For the internal package owner, the same anonymous endpoint also carries one
fixed reverse-direction recovery request. Its fixed reason and the transit
endpoint's path-free device/inode identity bind the frame to the generation;
the guardian accepts only its own identity, while markers and PIDs remain
observation-only. A malformed or cross-wired request grants no authority and
cannot initiate cleanup. A valid request or independently observed exact peer
EOF, including EOF after rejected bytes, may enter the existing typed owner-loss
cleanup; that authority comes from the EOF rather than the rejected frame and
never directly grants success, release, reap, or numeric-PID signalling. Only an
eligible retained deadline/cleanup state may retry once. Recovery racing an
already-written lifecycle control may drain one state-valid command without
minting its ACK, proof, or normal disposition.
At a nonrecoverable retained state, a recovery-transport failure, or a second
retention after that sole retry, the guardian consumes the completion endpoint,
attempts the retained record and write-half shutdown once, and parks the exact
typed provider/terminal owner. The parked guardian deliberately keeps that
exact typed owner reachable in its non-returning park loop for the remaining
process lifetime; this terminal state
is not retryable after the sole retry is consumed. Publication failure such as
`EPIPE` does not release that owner and cannot mint `CFCMP`.
Missing or trailing completion data and early-exit, nonzero, signalled, timeout,
second-signal, or forced-kill outcomes retain the relevant authority and park;
an accidentally dropped ambiguous App owner aborts without sending another
signal.

This recovery capability is live and generation-local. It exists only on the
anonymous endpoint retained by that running owner/guardian generation, is never
persisted, and does not survive loss of both authorities or a machine restart.
It is separate from Calcifer's existing cold conversation resume, which reopens
persisted history but does not recover a dead process or in-flight operation.

That graceful-drain proof is deliberately narrow. It records the reviewed
direct-child behavior of Codex `0.144.4`; it does **not** prove that every
arbitrary descendant which called `setsid(2)` has disappeared. Issue #55's
zero-residue scope is Calcifer-owned direct children and recorded known process
groups plus identity-checked runtime-directory, FD, and socket evidence.
The separate package smoke is intended to show that the official shell-command
path's detached probe inherits none of Calcifer's eight live supervisor
authority/control descriptors or denied supervisor/authentication environment,
not that Calcifer can enumerate or reap all possible non-child descendants.
Containment and accounting for escaped `setsid(2)` descendants is tracked by
issue #56 and is not claimed by #55.

Two independent official-package scenarios are configured. On 2026-07-20, the
final Issue #54 candidate source passed the normal-session scenario twice and
the retained-recovery scenario once on Apple silicon; the required Ubuntu
24.04/macOS matrix readback remains pending. The normal-session scenario runs the
official App Server and remote TUI through the production coordinator, guardian,
provider-session, PTY, input-gate, and job-control implementations under a test-
owned outer-terminal harness. Its acceptance checks cover initial and resumed
gates, resize, group-wide stop/continue, terminal restore, exact child waits,
scoped runtime cleanup, and provider-release-gated completion. The retained-
recovery scenario is separately designed to stop at
`RetainedCleanupPending`, prove that the checkpoint itself grants no recovery
authority, send the one generation-bound recovery request, and require the same
provider-release and cleanup gates. The package parent is designed to create the
completion endpoint, pass it across real parent-to-coordinator and coordinator-
to-guardian `exec` boundaries, and accept only the exact completion frame
followed by EOF. The guardian helper enters the shared production guardian-
bootstrap core, but its post-admission loopback rewrite and fixed observation
root, the package role dispatcher, and the outer terminal remain test-specific.
The test-specific dispatcher does not execute the production
`CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE` dispatcher/parser or persistent
shell-anchor role and makes no parser coverage claim.

A separate non-ignored deterministic package fixture covers all
seven closed production recovery checkpoints: startup queued, ready, active,
suspended, retained quiescing, retained restore pending, and retained cleanup
pending. It is designed to use the exact production coordinator, guardian, and
session graph while replacing only official compatibility/provider behavior
through a sealed `cfg(test)` capability seam and a strict owner-private wrapper. The
fixture is credential-free and loopback-only; production builds do not parse its
selector or compatibility override. A checkpoint is observation only: the test
must first prove that it neither completes nor terminates the generation, then
send the sole `CFRCR` request. The first four checkpoints are expected to end as
failed-clean and the three retained checkpoints as completed-clean. This fixture
is deterministic recovery evidence, not Codex-version compatibility evidence,
and its fourth namespace proof also requires the identity-checked private
compatibility stage parent to be empty. All seven cases passed three consecutive
local runs from that candidate source; the cross-platform CI readback remains pending.

If the `cfg(test)` package harness observes exact retained evidence or otherwise
cannot complete the four-proof cleanup gate, it emits one fixed, redacted
failure subtype and terminates the libtest process with a fixed nonzero
`_exit`-equivalent status while the Rust owners are still live. That test-only
terminal failure runs no destructors, produces no signal-driven core dump, and
closes the libtest descriptor table without running an unproved coordinator
TERM/KILL fallback, setting a completion proof, deleting scratch, or reporting
cleanup success. It replaces the former unbounded package-test park so hosted
CI cannot hide the failure behind its job timeout; it is not production
retained-owner behavior and grants no authority over descendants in another
session. The regression test launches both an exiting helper and a deliberately
parked helper behind a readiness handshake and bounded exact-child wait, then
kills and reaps only that helper if the bound expires. Production
guardian/anchor retained owners continue to park their concrete typed
authority. A failed recovery-request attempt is reported only as a consumed
attempt with an unknown transport boundary; shutdown failure is not described
as a confirmed write-half close.

Inference count is a closed scenario expectation. Early deterministic
checkpoints require zero model requests; retained deterministic checkpoints and
the normal live-turn flow are designed to require exactly one bounded JSON
`POST /v1/responses` with the synthetic model, `stream=true`, the pinned JSON/SSE
media headers, and no authorization or ChatGPT account header. The typed call-
count observation is joined as required harness evidence. A missing request when
one is required, a duplicate request, or any malformed or credential-bearing
request fails closed without logging a body or token. Usage/reset-credit
requests retain their separate synthetic credential check.

The package harness records its internal cleanup fence when the generation
starts. Every operation-phase wait is capped at one fixed recovery start, so
drip progress cannot renew a per-phase timeout or consume the reserved cleanup
budget. The harness then asks the guardian to recover before any exact-child
termination fallback. Scratch is deleted only after four independent proofs:
exact coordinator-child wait; the exact provider-release-only
`CFCMP\x01\r\n` record followed by EOF, which is not session or shell success;
absence of every reported known process group; and an identity-checked empty
runtime with zero retained FD and socket references. The CI workflow runs
`contracts`, `official-tui-normal`, and `official-tui-recovery` as independent
Ubuntu 24.04/macOS matrix scenarios behind one stable aggregate gate. It builds
and discovers the exact libtest before the OS-specific boundary. macOS provides
the native functional probe; Ubuntu runs both official scenarios without a
fallback in a fresh loopback-only network namespace after proving an exact
environment allowlist, no inherited socket FD, zero capabilities, and
`NoNewPrivs`. The two normal local runs and one retained-recovery local run are
green; the matrix readback remains pending. The watchdog bounds its direct
command group, while descendants that deliberately create another session
remain an explicit ephemeral-runner teardown boundary rather than a claimed
process-tree cleanup.

Example human output:

```text
codex@work [available]
  Codex
    primary: 41% used · 59% remaining (display) · 300m window · resets 2027-01-15T08:00:00Z
    secondary: 70% used · 30% remaining (display) · 10080m window · resets 2027-01-20T08:00:00Z
  reset credits: 2 available
    codexRateLimits · available · expires 2027-02-01T08:00:00Z
  observed 2026-07-15T12:34:56Z · fresh · codex_app_server
  compatibility compatible · Codex 0.144.4 · tested 0.144.4 · adapter 0.1.0-alpha.4
```

Stable JSON adds `codex_version`, `adapter_version`, and a `compatibility`
object for every profile. The object reports `compatible`, `incompatible`, or
`unverified`, the protocol name, and Calcifer's explicit tested-version set.
Only `compatible` observations can contain authoritative usage; every failure
still has `availability: "unknown"` and cannot authorize future failover.

The remaining percentage is explicitly display-only. Codex rounds the upstream used percentage, so displayed `0% remaining` is not by itself proof that the provider rejected the account. Calcifer reports `exhausted` only when the structured response contains a recognized `rateLimitReachedType`; otherwise a rounded 100% result is `unknown` for failover purposes.

`doctor` remains credential-free. It checks the host and whether executables named `codex` and `claude` are discoverable on `PATH`; it does not execute them or read provider state.

`update check` is also credential-free and never opens the profile registry,
provider configuration, or an authentication store. It reads only the public
`kazu-42/calcifer` GitHub Releases API through fixed HTTPS hosts, selects the
highest strict SemVer in exactly one `stable` or `preview` channel, and requires
an immutable release. The command selects only the archive for the binary's
exact Rust compile target; an unsupported target succeeds as
`target_unsupported` instead of substituting a different ABI. It downloads only
the bounded v1 manifest and `SHA256SUMS`, verifies their local bytes against the
release-asset digests and each other, and does not download or claim to verify
the archive itself. Network, schema, redirect, pagination, and integrity
failures are non-zero; an absent channel succeeds as `no_release_in_channel`.

Example JSON envelope:

```json
{
  "schema_version": 1,
  "command": "doctor",
  "calcifer_version": "0.1.0-alpha.4",
  "ok": true,
  "status": "warn",
  "checks": []
}
```

For structured `doctor`, `auth list`, `auth verify`, `auth rename`,
`auth remove --yes`, `status`, and `update check` results, `--json` emits one
JSON document on stdout. Rename reports `action: "rename"`, whether the alias
changed, the old and new local references, and the existing non-secret profile
record. Remove reports `action: "remove"`, `removed: true`, and the removed
non-secret profile record; JSON removal is accepted only with explicit `--yes`.
Interactive `auth add`, `run`, and `resume` reject `--json` because the official
provider owns the terminal and mixing its stream with a Calcifer JSON document
would break the contract. Identity JSON contains only Calcifer-local profile
metadata and never the private fingerprint, identity-key ID, or provider
account scope. Update JSON separates immutable-release and manifest-declared
attestation publication evidence from locally verified manifest/checksum bytes,
and always marks the un-downloaded archive `not_downloaded`. Usage and update
failures emit one redacted JSON document on stderr with a non-zero exit code.
Clap's standard `--help` and `--version` output remains text even when `--json`
is present. Within schema version 1, existing field names and meanings will
remain stable; new fields may be added.

## Planned interface

The following pool and default-selection commands remain design targets, not an implemented quick start:

```console
# Select a default for future processes, or pin one invocation.
calcifer use codex work

# Opt in to a bounded failover pool within one trust domain.
calcifer pool create codex personal --profiles personal-a,personal-b
calcifer supervise codex@personal
```

Arguments after `--` are arguments to the provider adapter's resolved, permission-checked `codex` executable; users do not supply an arbitrary executable. Account/provider-routing flags such as `-c`, `--profile`, `--oss`, `--local-provider`, and remote-routing options are rejected, as are `-C`/`--cd`, dynamic `--enable`/`--disable` feature overrides, and non-UTF-8 arguments that cannot be mediated safely. Calcifer forces profile-local file storage for both CLI and MCP OAuth credentials on every managed invocation. Existing pre-alpha profiles with the previous exact managed config remain usable because the per-invocation overrides are authoritative; new profiles persist both settings. Calcifer does not yet cryptographically verify binary provenance, so users remain responsible for installing the official CLI on a trusted `PATH`. Unimplemented commands fail as unknown commands rather than pretending to succeed.

## What "automatic failover" will mean

"Token limit" can refer to different things. Calcifer's planned selection logic concerns a provider-reported usage allowance or quota window, not a model context window.

Failover will follow conservative semantics:

- It is disabled by default and limited to a user-created pool of explicitly authorized profiles.
- A pool cannot cross provider or configured trust-domain boundaries.
- Only authoritative, fresh `exhausted` state permits selecting another profile. A rounded display value of `0% remaining`, authentication failure, provider error, network failure, unknown output, or stale status cannot authorize a switch.
- A pool is traversed at most once per invocation and uses cooldown state to prevent loops.
- Calcifer never hot-swaps credentials in a running process.
- After the old child has stopped, the supervisor will continue the same user-visible conversation under the selected profile. Internally, the preferred handoff forks the validated source rollout into a new profile-local Codex thread, so the logical conversation stays stable while the provider thread ID changes. Calcifer never automatically replays the last command or prompt; a partially completed turn may already have changed files or external systems.
- Before launch, Calcifer shows the local profile alias, provider, trust domain, and selection reason without exposing provider account identifiers.

Same-profile resume delegates the final operation directly to the official CLI in the selected home. Calcifer uses the pinned stable `thread/list` and `thread/read(includeTurns=false)` App Server projections only to capture and validate the opaque thread key; it never persists transcript content. Cross-profile continuation is a required part of the planned failover experience, but its upstream import field is experimental: stable Codex thread lookup is scoped to one `CODEX_HOME`. Calcifer will use a separate version-gated target-profile App Server to fork a validated source rollout into a new target-profile thread, then attach the official TUI over a private local transport. The handoff stays inside one configured trust domain, preserves one writer per rollout, and restores history without resubmitting a turn. See [ADR 0001](docs/adr/0001-cross-profile-conversation-handoff.md).

## Provider direction

| Capability | Status | Direction |
| --- | --- | --- |
| Read-only environment diagnostics | Implemented | No credential access |
| Credential-free update check | Implemented | Strict stable/preview SemVer, exact compile target, immutable v1 manifest and checksum verification; no archive download |
| Codex profile isolation | Implemented on Unix | One `CODEX_HOME` per profile; official Codex login and refresh |
| Same-profile Codex resume | Implemented on Unix for Codex 0.144.4 | Tracked workspace head, explicit exact thread ID, or official `--last`; no prompt replay |
| Private Codex identity binding | Implemented for 0.144.4 ChatGPT auth | HMAC equality only; duplicate aliases and credential drift fail closed |
| Codex usage observation | Implemented on demand for idle profiles | Structured App Server response; active profiles need public wiring of the internal typed monitor |
| Reset-credit visibility | Implemented read-only | Count and safe expiry/status detail; opaque IDs are redacted |
| Pinned supervised Codex integration | Internal implementation present; local Apple-silicon acceptance green, Ubuntu 24.04/macOS CI pending for 0.144.4 | Real App Server and remote TUI through the production coordinator/guardian session, typed monitor, PTY gate, and job-control implementation under a test-owned harness. Two consecutive normal runs and one retained-recovery run passed locally. Independent package scenarios share the production guardian-bootstrap core through bounded test seams, cross real parent-to-coordinator-to-guardian `exec` boundaries with the completion endpoint, and check the provider-release-gated exact frame plus EOF. Linux adds a fail-closed loopback-only direct-IP egress boundary; macOS remains native functional evidence. They deliberately bypass the production `CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE` dispatcher/parser and persistent shell-anchor role. No public supervised run/resume |
| Opt-in profile pools | Design | Same provider and trust domain; bounded selection |
| Cross-profile conversation handoff | Internal Linux/macOS target reservation and same-profile supervisor integration implemented | Transition journal, target fork, pool selection, crash recovery, and user-visible switching remain disabled; the planned version-gated fork creates a target-profile thread in one logical conversation |
| Claude setup-token profiles | Experimental plan | OS credential store where officially supported |
| Claude subscription OAuth replication | Not planned for MVP | No undocumented OAuth endpoint or Keychain-name emulation |
| Mid-session account hot-swap or command replay | Non-goal | Unsafe side-effect semantics |

Calcifer will prefer documented provider interfaces and official CLI behavior. Provider compatibility can break when a CLI or credential format changes; unsupported or ambiguous states must stop rather than guess.

The Linux, macOS, and Windows CI matrix still compiles and tests the portable surface. Managed registration is currently enabled only on Unix, where private directory/file modes are enforced. Windows registration fails closed until current-user-only ACL creation and recovery are verified.

## Security model

Calcifer is a local profile manager and process wrapper, not a credential broker or sandbox.

Core invariants for implemented and future paths are:

1. One process uses one immutable profile identity for its entire lifetime.
2. Calcifer never copies managed credentials into global `~/.codex` or global Claude state.
3. Only official CLI authentication and refresh mechanisms are used.
4. Secrets and opaque reset-credit identifiers never enter Calcifer logs, command arguments, diagnostics, telemetry, or real test fixtures.
5. Unknown quota state and authentication errors never authorize a switch.
6. State changes are permission-checked, atomic, bounded, and recoverable.
7. Old rotated credentials are never restored over newer credentials.
8. Credential-bearing environments are passed only to the selected adapter's validated executable, never to an arbitrary user-supplied command.
9. A credential profile and a logical conversation have independent lifecycles; a handoff may move the conversation only between stopped processes in one explicit trust domain.
10. Resume restores persisted history but never replays an interrupted prompt or tool action.
11. Ambient Codex credentials, authentication/provider endpoints, alternate
    managed config/state paths, remote execution and connector credentials,
    test hooks, and transcript/trace paths cannot override a selected Calcifer
    profile.
12. Repository-local Codex configuration cannot replace managed authentication,
    provider routing, dynamic feature policy, project-root discovery, or state
    locations; unknown future settings fail closed until reviewed.

File-based Codex credentials remain readable by the current OS user and the official Codex CLI; Calcifer is not an encrypted vault. Calcifer also does not sandbox the wrapped CLI, its hooks, or commands executed from the current repository.

See [Architecture](docs/architecture.md), [ADR 0001: cross-profile conversation handoff](docs/adr/0001-cross-profile-conversation-handoff.md), [ADR 0003: supervised Codex session](docs/adr/0003-supervised-codex-session.md), [Provider compatibility](docs/provider-compatibility.md), [Security model](docs/security-model.md), and [Security policy](SECURITY.md) before contributing to authentication, storage, process execution, or failover behavior.

## Build from source

Prerequisites:

- Rust 1.85 or newer
- Git
- The official Codex CLI for profile registration, launch, resume, or status

```console
git clone https://github.com/kazu-42/calcifer.git
cd calcifer
cargo test --all-targets --all-features --locked -- --test-threads=1
cargo run -- doctor
```

Install the current pre-alpha binary locally:

```console
make install-local
calcifer --json doctor
```

The default install prefix is `~/.local`. Override it with `make install-local PREFIX=/your/prefix`.
If `~/.local/bin` is not on `PATH`, run `~/.local/bin/calcifer --json doctor` or add that directory to `PATH`.

## Binary releases

Starting with `v0.1.0-alpha.3`, Calcifer publishes pre-release archives for
Linux glibc 2.35+ on x86-64/ARM64, macOS Intel/Apple silicon, and Windows x86-64 on the
[GitHub Releases page](https://github.com/kazu-42/calcifer/releases). Every
release includes SHA-256 checksums and GitHub artifact attestations minted by
the release workflow over the assembled release assets.
The binaries are not yet code-signed or notarized.

The Linux binary can run on the supported glibc baseline, but destructive
`auth remove` and interrupted-removal recovery additionally require Linux
kernel 5.8 or newer. On an older kernel those operations stop before mutation;
other non-destructive commands do not inherit this kernel requirement.

Download only the archive for your operating system and architecture, verify it
before installation, and keep in mind that Calcifer is still pre-alpha. See the
[release and rollback runbook](docs/releasing.md) for exact checksum,
attestation, install, uninstall, and recovery commands.

After the first immutable manifest-v1 release is published, inspect the exact
channel and compile-target result before downloading an archive:

```console
calcifer update check
calcifer --json update check --channel preview
```

The checker validates release metadata plus the downloaded manifest and
checksum bytes. It intentionally leaves archive download, archive-byte digest
verification, and installation as separate explicit operations.

## Development

```console
rustup toolchain install 1.85.0 --profile minimal
make fmt
make lint
make test
make supervisor-msrv
make check
```

The CI workflow is configured for checksum-pinned GitHub Actions linting,
formatting and Clippy on Rust 1.96, the stable Linux/macOS/Windows all-feature
test matrix run serially because process, signal, environment, and PTY tests
share process-global and kernel-mediated state, deterministic archive-package
tests, an MSRV compile check, and the full library unit suite plus
`tests/supervisor.rs`, run serially twice on Linux and macOS at Rust 1.85. Linux
and macOS jobs are additionally configured to download the
architecture-specific official Codex `0.144.4` archive, verify its
pinned SHA-256 digest and single binary, and run three independently budgeted
matrix scenarios. `contracts` runs the complete #28 handoff probe plus the #54
live-turn one-`SIGTERM` App drain, `setsid(2)` descriptor/environment-isolation,
and typed-monitor success/redacted-error probes. `official-tui-normal` is
designed to exercise the production coordinator/guardian session, PTY, input
gate, resize, and stop/resume path with the official remote TUI.
`official-tui-recovery` independently targets #55's retained-cleanup recovery
and four-proof deletion gate. Each official scenario has its own outer watchdog,
and one stable aggregate job requires every matrix entry. Their completion
endpoint is designed to cross real package-parent-to-coordinator and
coordinator-to-guardian `exec` boundaries, with the parent configured to accept
only the provider-release-gated exact frame followed by EOF. The guardian helper
enters the shared production guardian-bootstrap core, but the test-only role
dispatcher does not execute the production
`CALCIFER_INTERNAL_CODEX_SUPERVISOR_ROLE` dispatcher/parser or persistent shell-
anchor role. These are version-specific compatibility and recovery checks, not
a sandbox or proof that arbitrary detached descendants are absent. Local
Apple-silicon runs are green; Ubuntu 24.04/macOS workflow readback remains
pending. See
[CONTRIBUTING.md](CONTRIBUTING.md) for security-sensitive review expectations.

## Roadmap

The current and next slices keep Codex profile isolation with no shared runtime home:

1. **Implemented:** private Unix registry, profile-name validation, ownership markers, and atomic metadata writes.
2. **Implemented:** `auth add/list/verify/remove`, private Codex identity binding, `run`, same-profile `resume`, profile leases, and structured on-demand status.
3. **Implemented:** exact same-profile thread capture, crash reconciliation, no-argument cold restore, and journaled local profile removal. Safe reauth/re-key flows remain.
4. Add observation caching and adaptive refresh without aggressive polling; the on-demand status version/schema gate is implemented.
5. Add explicit same-trust-domain pools and fail-closed automatic selection.
6. Add version-gated cross-profile conversation handoff as the default successful failover path; the no-gap Linux/macOS target-reservation primitive and default-unused pinned same-profile provider/monitor/PTY implementation are present, while their deterministic and official-package acceptance evidence, public supervisor UX, transition journaling, authoritative selection, target-fork integration, and cross-profile crash recovery remain pending. Preserve one profile-local writer per lineage generation.
7. Add Claude only through provider-supported authentication and usage-observation surfaces.

Detailed gates and non-goals are tracked in [docs/roadmap.md](docs/roadmap.md).

## Contributing and security

Issues and focused pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

Do not put credentials, tokens, `auth.json`, `.credentials.json`, full environments, account identifiers, or raw debug logs in a public issue. Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Acknowledgements

Calcifer's profile-isolation direction was inspired in part by [Orca](https://github.com/stablyai/orca), an MIT-licensed project by Lovecast Inc. Calcifer's initial scaffold is an independent implementation and does not currently copy Orca source code. If upstream code is adapted later, its source revision and MIT notice will be recorded alongside the adapted code.

## Independence and trademarks

Calcifer is an independent project and is not affiliated with, endorsed by, or sponsored by OpenAI, Anthropic, or the Orca project. Codex, Claude, Claude Code, OpenAI, Anthropic, and Orca are names or trademarks of their respective owners.

Users are responsible for complying with provider terms, organization policy, account-sharing rules, and local law. Calcifer must only be used with profiles the user owns or is explicitly authorized to use.

## License

Calcifer is licensed under the [MIT License](LICENSE).
