# Architecture

> Status: evolving pre-alpha architecture. Unix Codex profile registration, pinned launch, same-profile resume, and structured on-demand status are implemented. The cross-profile conversation handoff design is accepted; its supervisor and automatic failover implementation remain future work.

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
| Conversation lineage registry | Bind one logical conversation to ordered profile-local thread generations | Treat a credential profile ID as the conversation ID |
| Provider adapter | Build an isolated environment and classify supported structured signals | Reimplement undocumented OAuth flows or scrape TUI text |
| Profile lease | Serialize profile mutation, usage probes, and child lifetime | Rely on PID files as the lock authority |
| Conversation lease | Serialize lineage transitions and rollout imports across profiles | Allow two generations to write one rollout |
| Selector | Choose one profile from an explicit pool | Cross trust domains or loop indefinitely |
| Process supervisor | Own the profile App Server, attach the official TUI, observe events, forward signals, and preserve exit semantics | Replay prompts or commands, or answer provider approval requests |
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
13. **Conversations have lineage.** Every provider thread is bound to its credential profile and canonical working directory, while one user-visible conversation may advance through multiple profile-local thread generations in one trust domain.
14. **Resume is not replay.** Restoring persisted conversation history never resubmits an interrupted prompt, command, or tool action.
15. **Repository configuration cannot route accounts.** Interactive launch accepts only version-reviewed repository settings and binds the final provider to the canonical working directory that was inspected.

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

The display name is not used as a filesystem path. A generated opaque ID is
mapped from a validated, normalized display name. Calcifer writes a minimal
managed `config.toml` and revalidates it with a Codex-version-scoped semantic
policy. Supported project trust and reviewed user settings may change, while
account/provider routing, state locations, dynamic extensions, and project-root
discovery remain Calcifer-owned. Top-level role definitions and any
auto-discovered `CODEX_HOME/agents` node are rejected because role files are
indirect complete configuration layers; managed role configuration requires a
future provenance-aware mediation design. MCP OAuth callback URL and port are
also rejected because they alter the reviewed connector authorization route.
Existing pre-alpha profiles with
only `cli_auth_credentials_store="file"` remain accepted during upgrade, while
new profiles persist both file-store settings. Calcifer forces both credential
stores to `file` on every provider invocation and rejects child arguments that
can change account/provider routing. Codex then updates its own profile-local
credentials. No managed-to-runtime credential copy-back step is needed. See
the [managed config specification](../specs/managed-codex-config.md).

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

Stable `thread/resume` lookup is scoped to the current `CODEX_HOME`. Codex 0.144.4 also exposes experimental external rollout paths for resume and fork, but Calcifer does not enable them yet. The accepted cross-profile design uses a target-profile App Server to fork validated source history into a new target-profile rollout. It requires same-trust-domain policy, source-profile provenance, canonical containment under a Calcifer-managed sessions root, one writer per lineage generation, version gating, and no prompt replay; see [ADR 0001](adr/0001-cross-profile-conversation-handoff.md).

## Implemented Codex usage observation

For every selected idle profile, Calcifer holds the exclusive profile lease and
starts the resolved, permission-checked executable named `codex` with the
verified profile home as `CODEX_HOME` and a private neutral runtime directory
as its cwd:

```text
CODEX_HOME=<managed-home> codex \
  -c 'cli_auth_credentials_store="file"' \
  -c 'mcp_oauth_credentials_store="file"' \
  app-server --stdio
```

It completes the stable JSONL initialization handshake with `experimentalApi: false`, requires the explicitly tested Codex `0.144.4` client-scoped user-agent, and canonicalizes the returned `codexHome` against the selected managed home. Only then does it call `account/rateLimits/read`. An untested version, changed initialize schema, or different home closes the probe before the usage request. Calcifer closes stdin, waits briefly for a clean provider exit, and only then kills/reaps a stuck probe. The bounded no-turn app-server inherits only the provider side of the lease; if the status parent is killed, a second writer remains blocked until that app-server exits on stdio EOF. Input is bounded to a 1 MiB JSONL line. Normalized output includes all returned metered buckets, primary and secondary windows, reset timestamps, workspace credits, individual spend controls, and safe reset-credit count/status/expiry fields. Opaque reset-credit IDs and backend display copy are discarded before the public model is constructed.

The app-server command is still marked experimental at the CLI level even though these request types are on its stable protocol subset. Status output records the detected Codex version when safely parseable, the Calcifer adapter version, protocol, tested version set, and `compatible | incompatible | unverified` state. Unknown methods, malformed schemas, auth errors, timeouts, and spawn failures are explicit `unknown` observations. Calcifer does not fall back to `/status` text scraping or undocumented backend endpoints. Binary provenance is not yet cryptographically verified and remains a user-level `PATH` trust assumption.

`usedPercent` is rounded by Codex. Calcifer derives `remainingPercent = clamp(100 - usedPercent)` for display only. A recognized `rateLimitReachedType` is required to classify a snapshot as exhausted; rounded 100%, null fields, and errors remain unknown for automatic-selection purposes.

The one-shot probe cannot inspect a profile while its `run` or `resume` child owns the exclusive lease. Such a profile reports `profile_busy` / `unknown`. Multiple profiles are currently probed sequentially with a per-profile timeout. Continuous active-session observations, bounded parallel refresh, TTL/backoff, and cached last-known state belong in a future profile-owned app-server/supervisor so credential refresh retains exactly one owner.

The verified upstream versions, exact fields, and source links are recorded in [Provider compatibility notes](provider-compatibility.md).

## Planned supervised failover and conversation handoff

```text
resolve pinned profile or explicit pool
  -> reject cross-provider or cross-trust-domain candidates
  -> launch a profile-owned App Server and attach the official TUI locally
  -> observe structured turn and rate-limit events
     -> ordinary completion/error: keep the current profile or stop
     -> confirmed exhaustion: revalidate under the current lease
  -> acquire handoff/conversation leases, retain the source lease, reserve a fresh target
  -> stop and reap the source TUI and App Server while retaining source ownership
  -> validate the source rollout and fsync a prepared handoff
  -> start the target profile App Server
  -> version-gated thread/fork(path=source rollout, effective settings)
  -> verify new lineage ID, target containment, and unchanged source
  -> atomically commit the new lineage generation
  -> attach the official TUI to the target thread before accepting input
  -> release source/transition leases; retain the target lifetime lease
  -> continue monitoring; never replay the failed turn

A pool is traversed at most once per invocation.
```

The current `run` command does not restart or re-submit a command after the child begins execution. The planned supervisor treats credential profiles and conversation lineage as separate aggregates. It continues the same user-visible conversation after failover by creating a target-profile Codex thread from the validated source rollout, but it must not resubmit the failed turn. The wrapped agent may already have produced external side effects before reporting quota exhaustion. The supervisor connection remains event-only and never races the official TUI to answer approvals or other server-initiated requests; no new turn is admitted without an attached TUI. The full decision and recovery model is in [ADR 0001](adr/0001-cross-profile-conversation-handoff.md).

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
- force profile-local file storage for CLI and MCP OAuth credentials on every
  operation and reject provider arguments that can override the account,
  provider, endpoint, profile, or remote route;
- reject child working-directory and dynamic-feature overrides, and reject
  non-UTF-8 provider arguments that cannot be mediated safely;
- after acquiring the profile lease, canonicalize the interactive working
  directory and inspect every real, bounded `.codex` layer from the nearest
  `.git` root to that directory against a Codex-version-scoped safe-key policy,
  rejecting every `.codex/agents` node before reading an optional
  `config.toml`;
- repeat that inspection in the provider guardian after spawn authorization,
  then set the final Codex process cwd explicitly to the inspected canonical
  directory;
- sanitize the internal run/resume coordinator and guardian before spawn, then
  construct every final login, run, resume, and App Server process through one
  managed command policy that removes ambient Codex credentials, authentication and
  endpoint overrides, alternate config/state paths, remote execution routes,
  connector credentials, transcript/trace paths, provider test hooks, and
  future override families;
- run login and status from a private neutral runtime directory with its own
  `.git` boundary, independently of `CALCIFER_HOME`, so account-only operations
  cannot discover repository-local configuration through an ancestor;
- avoid logging raw arguments or the child environment.

The official CLI still receives ordinary terminal, locale, proxy, and CA
environment needed for interactive and enterprise operation. Calcifer does not
claim to protect credentials from a hostile same-user proxy or trust store.

The wrapped CLI, repository hooks, tools, and provider remain outside Calcifer's sandbox because Calcifer does not provide one.

The coordinator and guardian checks reduce replacement races but cannot stop an
actor that can mutate the repository tree, including same-user malware or a
different writer in a shared workspace, from changing files between the final
check and Codex's own read. A supported upstream switch that disables project
configuration, or an effective-configuration API with source provenance, would
be required to remove that residual boundary completely.

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
- cross-profile conversation handoff implementation following [ADR 0001](adr/0001-cross-profile-conversation-handoff.md);
- OS credential-store support for Claude setup tokens;
- trust-domain configuration and failover pool UX.

Credential-management support is a separate platform guarantee from the portable diagnostic surface. Each provider and OS combination must pass its permission, credential-store, process, and recovery tests before being marked supported.
