# Architecture

> Status: design target for a pre-alpha project. Only the read-only `doctor` command exists today.

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
| Registry | Store non-secret profile metadata and defaults | Store raw tokens in diagnostics or logs |
| Provider adapter | Build an isolated environment and classify supported signals | Reimplement undocumented OAuth flows |
| Profile lease | Serialize mutation and child lifetime for one profile | Rely on PID files as the lock authority |
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

## Codex profile model

The planned Codex adapter gives each profile its own managed home and launches Codex with that home directly:

```text
managed root/
  profiles/
    codex/
      <opaque-profile-id>/
        home/       <- CODEX_HOME for this profile
        metadata    <- non-secret identity and state
        lock        <- profile lifetime lease
```

The display name is not used as a filesystem path. A generated opaque ID is mapped from a validated, normalized display name. Calcifer will set file-backed credential storage in the profile configuration when that is the supported Codex contract, then let Codex update its own profile-local credentials. No managed-to-runtime credential copy-back step is needed.

Different profiles may run concurrently. Until provider refresh concurrency is proven safe, the same profile has at most one active official CLI child.

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

Calcifer will not restart or re-submit a command after the child begins execution. This preserves a conservative at-most-one-launch invariant even though the wrapped agent may already have produced external side effects before reporting quota exhaustion.

## Filesystem and credential mutations

On Unix, the planned managed root uses directory mode `0700`; credential and lock files use `0600`. On Windows, credential-bearing features require verified current-user-only ACLs with equivalent confidentiality or fail closed. Security-sensitive paths must reject symlinks, non-regular files, unexpected ownership, path traversal, separators in names, and paths outside an ownership-marked managed root.

Calcifer-owned metadata updates follow a same-filesystem atomic-write sequence:

1. Create a random temporary file in the managed directory with exclusive creation and Unix mode `0600` or a verified Windows current-user-only ACL.
2. Write all content and `fsync` the file.
3. Atomically rename it to the destination.
4. `fsync` the parent directory.

Registration and re-authentication happen in a staging directory and become visible only after provider identity, ownership, permissions, and expected file shape are verified. Credential rotation is never rolled back to an older token set; damaged credentials become `needs-reauth` instead.

## Process execution

The process supervisor will:

- let the provider adapter select the executable; `--` accepts provider arguments, not a command;
- resolve and canonicalize the configured official executable, with no repository-local override;
- reject repository-local, current-directory, world-writable, unapproved, or symlink-swapped executable paths;
- spawn the executable and argument vector directly, never through `sh`, `eval`, or string concatenation;
- make the `--` provider-argument boundary explicit;
- hold the profile lease for the entire child or PTY lifetime;
- forward termination signals and preserve the child exit status where the OS permits;
- avoid persisting child stdout or stderr by default;
- sanitize provider-specific conflicting authentication environment variables;
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

Before the first functional release, the project still needs reviewed ADRs for:

- the user-level registry format and platform paths;
- provider identity verification;
- process/PTY supervision on Linux, macOS, and Windows;
- the authoritative Codex usage signal and version gates;
- OS credential-store support for Claude setup tokens;
- trust-domain configuration and failover pool UX.

Credential-management support is a separate platform guarantee from the current doctor-only host support. Each provider and OS combination must pass its permission, credential-store, process, and recovery tests before being marked supported.
