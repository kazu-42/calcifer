# Calcifer

[![CI](https://github.com/kazu-42/calcifer/actions/workflows/ci.yml/badge.svg)](https://github.com/kazu-42/calcifer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

Calcifer is a pre-alpha, local-first Rust wrapper for running official coding-agent CLIs with isolated account profiles and structured usage visibility.

> [!WARNING]
> **Status: functional pre-alpha.** Codex profile registration, pinned launches, same-profile resume, and on-demand usage status are implemented on Unix. Automatic failover, cross-profile session handoff, remove/reauth flows, and verified Windows credential ACLs are not implemented yet.

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

# Read every idle registered profile, or one idle profile, without changing the global login.
calcifer status
calcifer status codex@work
calcifer --json status

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

Each registration gets a private, opaque directory and a complete profile-specific `CODEX_HOME`. The official CLI writes authentication, project trust, and session state there, so exiting Calcifer does not discard the conversation. Calcifer accepts supported Codex project-trust updates semantically while continuing to require profile-local file storage for both Codex account and MCP OAuth credentials and reject profile/provider routing overrides, including MCP OAuth callback URL and port overrides. Managed Codex role configuration is currently unsupported: both a top-level `agents` table and any auto-discovered `CODEX_HOME/agents` node fail closed because role files can add indirect complete configuration layers. `calcifer resume codex@work` remains the explicit official `codex resume --last` convenience; bare `calcifer resume` resolves Calcifer's exact tracked workspace thread and never falls back to `--last`.

Before interactive `run` and `resume`, Calcifer canonicalizes the working directory and checks every repository-local `.codex` layer from the nearest real `.git` root to that directory. Any `.codex/agents` filesystem node fails closed even when `config.toml` is absent; otherwise only a Codex 0.144.4-scoped set of repository settings that do not own managed authentication, provider routing, dynamic features, or state locations is accepted. Unknown keys, ambiguous filesystem nodes, invalid TOML, and files larger than 1 MiB fail before Codex starts. In a linked worktree, Codex 0.144.4 can additionally merge only `hooks` from the primary checkout; Calcifer does not resolve that external hook source, and repository hooks remain outside its sandbox guarantee. This preflight protects Calcifer's account-routing boundary, but it does not make repository hooks, plugins, tools, or code safe.

Account-only operations do not need repository context. `auth add` and `status`
therefore run the official CLI from a private runtime directory with its own
`.git` boundary, while retaining the selected profile-specific `CODEX_HOME`.
This remains isolated even when `CALCIFER_HOME` itself is stored inside a Git
repository with local Codex configuration.

For supported Codex 0.144.4 sessions, Calcifer captures the immutable `{profile ID, canonical cwd, thread ID}` binding in a separate private `conversations.json`. Bare `calcifer resume` validates that exact rollout under its source-profile lease and invokes `codex resume <exact-uuid>` without a prompt. A clean wrapper restart therefore restores the tracked history without an account selector or thread lookup. Interrupted and uncertain crash boundaries show a warning before reopening; missing, archived, incompatible, cross-profile, cross-cwd, corrupt, or ambiguous state stops before provider launch. Resume restores persisted history, not a dead process or in-flight tool call, and never resends the last prompt, approval answer, command, or tool call.

Normal `run` and profile-specific `resume` remain fail-closed when Calcifer cannot prove a complete capture inventory. `--untracked` is the explicit manual escape hatch for `run` or profile-specific `resume --last`: it performs no App Server inventory, refuses an unresolved pending launch in the workspace, durably marks the workspace as requiring selection before spawning Codex, retains a metadata-only in-flight ownership record until the official child exits, and prints a warning. That ownership prevents a concurrent exact resume under another profile from restoring a stale automatic head; an exact process that started first also cannot refresh over a later untracked marker. Bare `calcifer resume` remains disabled afterward until `calcifer resume codex@<alias> <exact-thread-id>` validates and restores a tracked head. The flag cannot be combined with an exact thread ID or bare resume; a provider argument named `--untracked` must follow the `--` separator as usual.

`status` starts the installed official `codex app-server` inside each idle profile and calls the structured `account/rateLimits/read` method. Before that read, it requires the tested Codex `0.144.4` initialize contract and verifies that the server reports the selected canonical `CODEX_HOME`. Untested versions, changed initialize data, a different home, or a changed usage schema fail closed as `unknown`; Calcifer does not send the usage request after an initialize-gate rejection. It displays all returned limit buckets, primary and secondary used/remaining percentages, reset times, workspace credit state, monthly spend control when present, and rate-limit reset-credit count and expirations. It does not scrape the interactive `/status` screen or read token values from `auth.json`.

An active `run` or `resume` holds a split exclusive lease because a second Codex process could race credential refresh and session writes. A launch coordinator owns one half and a provider guardian owns the other; either process surviving a selective crash keeps the profile busy until the exact provider exits. Consequently, status for that active profile is currently `profile_busy` / `unknown`; a list query inspects profiles serially with a per-profile timeout. Active-session monitoring, cached last-known observations, and automatic failover still require a profile-owned usage supervisor. Also, a Calcifer profile is a local alias: provider identity is not yet verified, so two aliases may point to the same underlying account and quota.

Example human output:

```text
codex@work [available]
  Codex
    primary: 41% used · 59% remaining (display) · 300m window · resets 2027-01-15T08:00:00Z
    secondary: 70% used · 30% remaining (display) · 10080m window · resets 2027-01-20T08:00:00Z
  reset credits: 2 available
    codexRateLimits · available · expires 2027-02-01T08:00:00Z
  observed 2026-07-15T12:34:56Z · fresh · codex_app_server
  compatibility compatible · Codex 0.144.4 · tested 0.144.4 · adapter 0.1.0-alpha.3
```

Stable JSON adds `codex_version`, `adapter_version`, and a `compatibility`
object for every profile. The object reports `compatible`, `incompatible`, or
`unverified`, the protocol name, and Calcifer's explicit tested-version set.
Only `compatible` observations can contain authoritative usage; every failure
still has `availability: "unknown"` and cannot authorize future failover.

The remaining percentage is explicitly display-only. Codex rounds the upstream used percentage, so displayed `0% remaining` is not by itself proof that the provider rejected the account. Calcifer reports `exhausted` only when the structured response contains a recognized `rateLimitReachedType`; otherwise a rounded 100% result is `unknown` for failover purposes.

`doctor` remains credential-free. It checks the host and whether executables named `codex` and `claude` are discoverable on `PATH`; it does not execute them or read provider state.

Example JSON envelope:

```json
{
  "schema_version": 1,
  "command": "doctor",
  "calcifer_version": "0.1.0-alpha.3",
  "ok": true,
  "status": "warn",
  "checks": []
}
```

For structured `doctor`, `auth list`, and `status` results, `--json` emits one JSON document on stdout. Interactive `auth add`, `run`, and `resume` reject `--json` because the official provider owns the terminal and mixing its stream with a Calcifer JSON document would break the contract. Usage failures emit one redacted JSON document on stderr with exit code `2`. Clap's standard `--help` and `--version` output remains text even when `--json` is present. Within schema version 1, existing field names and meanings will remain stable; new fields may be added.

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
| Codex profile isolation | Implemented on Unix | One `CODEX_HOME` per profile; official Codex login and refresh |
| Same-profile Codex resume | Implemented on Unix for Codex 0.144.4 | Tracked workspace head, explicit exact thread ID, or official `--last`; no prompt replay |
| Codex usage observation | Implemented on demand for idle profiles | Structured app-server response; active profiles need the planned supervisor |
| Reset-credit visibility | Implemented read-only | Count and safe expiry/status detail; opaque IDs are redacted |
| Opt-in profile pools | Design | Same provider and trust domain; bounded selection |
| Cross-profile conversation handoff | Required failover design | Not enabled; version-gated fork into a target-profile thread, tracked as one logical conversation |
| Claude setup-token profiles | Experimental plan | OS credential store where officially supported |
| Claude subscription OAuth replication | Not planned for MVP | No undocumented OAuth endpoint or Keychain-name emulation |
| Mid-session account hot-swap or command replay | Non-goal | Unsafe side-effect semantics |

Calcifer will prefer documented provider interfaces and official CLI behavior. Provider compatibility can break when a CLI or credential format changes; unsupported or ambiguous states must stop rather than guess.

The Linux, macOS, and Windows CI matrix still compiles and tests the portable surface. Managed registration is currently enabled only on Unix, where private directory/file modes are enforced. Windows registration fails closed until current-user-only ACL creation and recovery are verified.

## Security model

Calcifer is a local profile manager and process wrapper, not a credential broker or sandbox.

Core invariants for future implementation are:

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

See [Architecture](docs/architecture.md), [ADR 0001: cross-profile conversation handoff](docs/adr/0001-cross-profile-conversation-handoff.md), [Provider compatibility](docs/provider-compatibility.md), [Security model](docs/security-model.md), and [Security policy](SECURITY.md) before contributing to authentication, storage, process execution, or failover behavior.

## Build from source

Prerequisites:

- Rust 1.85 or newer
- Git
- The official Codex CLI for profile registration, launch, resume, or status

```console
git clone https://github.com/kazu-42/calcifer.git
cd calcifer
cargo test --all-targets --all-features --locked
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
release includes SHA-256 checksums and GitHub build-provenance attestations.
The binaries are not yet code-signed or notarized.

Download only the archive for your operating system and architecture, verify it
before installation, and keep in mind that Calcifer is still pre-alpha. See the
[release and rollback runbook](docs/releasing.md) for exact checksum,
attestation, install, uninstall, and recovery commands.

## Development

```console
rustup toolchain install 1.85.0 --profile minimal
make fmt
make lint
make test
make check
```

The CI contract covers formatting and Clippy on Rust 1.96, tests on Linux/macOS/Windows, deterministic archive-package tests, and an MSRV check on Rust 1.85. See [CONTRIBUTING.md](CONTRIBUTING.md) for security-sensitive review expectations.

## Roadmap

The current and next slices keep Codex profile isolation with no shared runtime home:

1. **Implemented:** private Unix registry, profile-name validation, ownership markers, and atomic metadata writes.
2. **Implemented:** `auth add/list`, `run`, same-profile `resume`, profile leases, and structured on-demand status.
3. **Implemented:** exact same-profile thread capture, crash reconciliation, and no-argument cold restore. Provider identity verification and safe remove/reauth flows remain.
4. Add observation caching and adaptive refresh without aggressive polling; the on-demand status version/schema gate is implemented.
5. Add explicit same-trust-domain pools and fail-closed automatic selection.
6. Add version-gated cross-profile conversation handoff as the default successful failover path; preserve one profile-local writer per lineage generation.
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
