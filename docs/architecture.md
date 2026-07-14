# Architecture

> Status: evolving pre-alpha architecture. Unix Codex profile registration, pinned launch, same-profile resume, and structured on-demand status are implemented. Automatic failover and cross-profile transcript handoff remain design work.

Calcifer is designed as a local orchestrator around official coding-agent CLIs. It selects an isolated profile, constructs a provider-specific child environment, and launches the official executable directly without a shell.

## Trust boundaries

```text
User
  |
  v
Calcifer parser and selector
  |---- local registry and quota observations
  |---- OS credential store, where supported
  |---- profile-specific CODEX_HOME
  |
  v
Resolved official CLI binary
  |
  v
Provider API

Untrusted inputs:
- the current repository, hooks, and configuration
- profile names and child arguments
- PATH and executable resolution
- provider CLI output and exit status
- quota observations
- filesystem state after interruption or a crash
```

A repository-local file must never be able to select an account or failover pool. Account routing is user-level security policy because changing profile may change the organization that receives source code, prompts, and conversation history.

## Planned components

| Component | Responsibility | Must not do |
| --- | --- | --- |
| CLI parser | Parse explicit commands and the `--` provider-argument boundary | Accept implicit external subcommands or an arbitrary executable |
| Registry | Store non-secret opaque profile metadata | Store raw tokens in diagnostics or logs |
| Provider adapter | Build an isolated environment and classify supported structured signals | Reimplement undocumented OAuth flows or scrape TUI text |
| Profile lease | Serialize profile mutation, usage probes, and child lifetime | Rely on PID files as the lock authority |
| Selector | Choose one profile from an explicit pool | Cross trust domains or loop indefinitely |
| Process supervisor | Spawn directly, forward signals, preserve exit semantics | Replay prompts or commands |
| Observation cache | Record bounded, timestamped usage state | Treat stale or unknown data as exhaustion |

## Normative invariants

Future code that violates one of these invariants requires an architecture decision record and a security review.

1. **One process, one profile.** Profile identity is immutable for the entire child lifetime.
2. **No global credential mutation.** Managed profiles are never activated by overwriting global Codex or Claude state.
3. **No implicit trust crossing.** Automatic selection stays within one provider and an explicitly configured trust domain.
4. **No automatic replay.** A command or prompt is launched at most once by one Calcifer invocation.
5. **Unknown means stop.** Unknown, stale, or unparseable usage state never authorizes failover.
6. **Authentication is not exhaustion.** Login, policy, suspension, network, and provider failures fail loudly.
7. **State transitions are atomic and bounded.** Partial registration or selection must be recoverable.
8. **Newer credentials win.** Rotated credentials are never replaced with an older backup during rollback.
9. **Secrets are not output.** Tokens and credential payloads never enter logs, diagnostics, arguments, telemetry, or fixtures.
10. **Providers own authentication.** Login and refresh stay in official, supported provider flows.
11. **Provider executable only.** Credential-bearing environments are passed only to the selected adapter's validated executable, never to an arbitrary user-supplied command.
12. **Selection is visible.** Before launch, Calcifer reports the local profile alias, provider, trust domain, and reason code without exposing stable provider identifiers.
13. **Sessions have provenance.** An automatically resumable thread is bound to the profile and canonical working directory that created it.
14. **Resume is not replay.** Restoring persisted conversation history never resubmits an interrupted prompt, command, or tool action.

## Codex profile model

The planned Codex adapter gives each profile its own managed home and launches Codex with that home directly:

```text
managed root/
  profiles/
    codex/
      <opaque-profile-id>/
        home/       <- CODEX_HOME, auth, sessions, and Codex state for this profile
        .calcifer-profile <- ownership marker
        profile.lock      <- coordinator side of the lifetime lease
        provider.lock     <- provider-guardian side of the lifetime lease
```

The display name is not used as a filesystem path. A generated opaque ID is mapped from a validated, normalized display name. Calcifer writes and revalidates an exact managed `config.toml`, forces `cli_auth_credentials_store="file"` on every provider invocation, and rejects child arguments that can change account/provider routing. Codex then updates its own profile-local credentials. No managed-to-runtime credential copy-back step is needed.

Different profiles may run concurrently. The same profile has at most one official CLI child or usage probe because either operation may refresh profile-local credentials.

The registry currently proves local profile provenance, not provider account uniqueness. It does not publish or compare a stable provider account ID, so two local aliases can still refer to the same ChatGPT account. Identity verification is required before aliases may safely participate in a failover pool.

## Implemented same-profile resume

Codex owns its rollout files and state database inside the profile-specific `CODEX_HOME`. Calcifer currently exposes:

```text
calcifer resume codex@<alias> <thread-id>
calcifer resume codex@<alias>              # delegates to codex resume --last
```

The exact thread ID is the reliable resume key. `--last` remains a convenience fallback and is not suitable for a future automatic cold restore because Codex filters it by the current working directory and multiple sessions may be eligible.

The current slice does not yet install a session hook or persist `{profile_id, cwd, thread_id}` automatically. That registry is required before Calcifer can cold-restore a session without the user supplying an ID. Restored state is the persisted conversation transcript; a dead process, stream, or in-flight tool call is not restarted.

Stable `thread/resume` lookup is scoped to the current `CODEX_HOME`. Codex 0.144.4 also exposes an experimental external rollout `path`, but Calcifer does not enable it. A future cross-profile handoff requires same-trust-domain policy, source-profile provenance, canonical path containment under a Calcifer-managed sessions root, a single-writer session lease, version gating, and no prompt replay.

## Implemented Codex usage observation

For every selected idle profile, Calcifer holds the exclusive profile lease and starts the resolved, permission-checked executable named `codex` from the verified profile home as:

```text
CODEX_HOME=<managed-home> codex -c 'cli_auth_credentials_store="file"' app-server --stdio
```

It completes the stable JSONL initialization handshake with `experimentalApi: false`, calls `account/rateLimits/read`, closes stdin, waits briefly for a clean provider exit, and only then kills/reaps a stuck probe. The bounded no-turn app-server inherits only the provider side of the lease; if the status parent is killed, a second writer remains blocked until that app-server exits on stdio EOF. Input is bounded to a 1 MiB JSONL line. Normalized output includes all returned metered buckets, primary and secondary windows, reset timestamps, workspace credits, individual spend controls, and safe reset-credit count/status/expiry fields. Opaque reset-credit IDs and backend display copy are discarded before the public model is constructed.

The app-server command is still marked experimental at the CLI level even though these request types are on its stable protocol subset. Unknown methods, malformed schemas, auth errors, timeouts, and spawn failures are explicit `unknown` observations. Calcifer does not fall back to `/status` text scraping or undocumented backend endpoints. Binary provenance is not yet cryptographically verified and remains a user-level `PATH` trust assumption.

`usedPercent` is rounded by Codex. Calcifer derives `remainingPercent = clamp(100 - usedPercent)` for display only. A recognized `rateLimitReachedType` is required to classify a snapshot as exhausted; rounded 100%, null fields, and errors remain unknown for automatic-selection purposes.

The one-shot probe cannot inspect a profile while its `run` or `resume` child owns the exclusive lease. Such a profile reports `profile_busy` / `unknown`. Multiple profiles are currently probed sequentially with a per-profile timeout. Continuous active-session observations, bounded parallel refresh, TTL/backoff, and cached last-known state belong in a future profile-owned app-server/supervisor so credential refresh retains exactly one owner.

The verified upstream versions, exact fields, and source links are recorded in [Provider compatibility notes](provider-compatibility.md).

## Planned failover state machine

```text
resolve pinned profile or explicit pool
  -> reject cross-provider or cross-trust-domain candidates
  -> use cached usage state only as a candidate prefilter
  -> acquire the candidate profile lease
  -> revalidate identity, credentials, and fresh authoritative usage under the lease
     -> available: display selection and launch exactly once
     -> exhausted: record cooldown, release the lease, and try the next candidate
     -> unknown: release the lease and stop without switching
  -> child exits
     -> confirmed exhaustion: record it for a future invocation
     -> auth/network/provider/parser error: stop without switching
     -> other exit: propagate the status
  -> release lease

A pool is traversed at most once per invocation.
```

The current `run` command does not restart or re-submit a command after the child begins execution. A future supervisor may reopen a persisted transcript only after the old child is confirmed stopped, but it must not resubmit the failed turn. The wrapped agent may already have produced external side effects before reporting quota exhaustion.

## Filesystem and credential mutations

On Unix, the implemented managed root uses directory mode `0700`; Calcifer-owned files and locks use `0600`. On Windows, registration currently fails closed because equivalent current-user-only ACL creation has not been verified. The current slice rejects invalid aliases, non-canonical opaque IDs, symlinked or non-regular managed files, permissive Unix modes, and ownership-marker mismatches. Owner-UID checks and hardened directory-relative open operations remain release gates.

Calcifer-owned metadata updates follow a same-filesystem atomic-write sequence:

1. Create a random temporary file in the managed directory with exclusive creation and Unix mode `0600` or a verified Windows current-user-only ACL.
2. Write all content and `fsync` the file.
3. Atomically rename it to the destination.
4. `fsync` the parent directory.

Registration happens in a staging directory and becomes visible only after the official login exits successfully and a private regular `auth.json`, ownership marker, and expected directory layout are present. The profile directory is renamed and its provider parent synced before registry publication. The registry rename is the visibility point: if the following directory sync fails, Calcifer preserves both the visible entry and credentials, reports `registry_commit_uncertain`, and tells the user to read back `auth list` rather than retry blindly. Stable provider identity verification, interrupted-staging recovery, re-authentication, and remove flows are not implemented yet. A failed normal login performs checked cleanup; a hard crash can leave a private orphan staging directory for later recovery tooling.

## Process execution

The current process launcher:

- let the provider adapter select the executable; `--` accepts provider arguments, not a command;
- resolve and canonicalize the `codex` executable found on `PATH`;
- reject executables inside the current repository, untrusted Unix owners, group/other-writable executable files, and non-sticky writable parent directories;
- spawn the executable and argument vector directly, never through `sh`, `eval`, or string concatenation;
- make the `--` provider-argument boundary explicit;
- delegate interactive launch to a coordinator plus provider guardian, each holding one side of a fixed-order split lease for the entire official provider lifetime;
- keep both interactive lease descriptors out of the provider process tree, so provider-started background tools cannot pin the profile after Codex exits;
- retain the provider-side lease if the coordinator is selectively killed, and retain the coordinator-side lease while tracking the exact provider PID if the guardian is selectively killed;
- fail closed by retaining the coordinator lease when a guardian disappears in the narrow ambiguous interval between spawn authorization and its provider-PID report;
- let every Calcifer wrapper layer catch terminal termination signals while the official provider receives its normal process-group delivery, so a provider that handles `SIGINT` remains attached to the foreground wrapper and cannot outlive every lease owner;
- preserve ordinary child exit codes; polished cross-platform signal forwarding and job-control semantics remain release gates;
- avoid persisting child stdout or stderr by default;
- remove `CODEX_API_KEY` and `OPENAI_API_KEY` before managed login, run, resume, and status operations;
- force file-backed credentials on every operation and reject provider arguments that can override the account, provider, endpoint, profile, or remote route;
- run login and status from the managed profile home so repository-local configuration cannot influence those account-sensitive operations;
- avoid logging raw arguments or the child environment.

The wrapped CLI, repository hooks, tools, and provider remain outside Calcifer's sandbox because Calcifer does not provide one.

## Error and rollback boundaries

Failures that must not trigger another account include:

- expired or invalid credentials;
- a required browser re-authentication;
- HTTP 5xx, DNS, timeout, or offline state;
- unsupported CLI versions or changed output formats;
- account suspension or policy denial;
- stale usage data or a failed status source.

Rollback applies to Calcifer metadata, default pointers, observation caches, and staged registration. It does not overwrite a newer credential with an older copy.

## Open design work

Before the first stable release, the project still needs reviewed ADRs for:

- provider identity verification;
- process/PTY supervision on Linux, macOS, and Windows;
- supported Codex version/schema gates and observation cache TTL/backoff;
- exact thread capture, interrupted-turn state, and cold-restore recovery;
- cross-profile transcript handoff or a decision to keep it out of scope;
- OS credential-store support for Claude setup tokens;
- trust-domain configuration and failover pool UX.

Credential-management support is a separate platform guarantee from the portable diagnostic surface. Each provider and OS combination must pass its permission, credential-store, process, and recovery tests before being marked supported.
