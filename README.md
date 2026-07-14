# Calcifer

[![CI](https://github.com/kazu-42/calcifer/actions/workflows/ci.yml/badge.svg)](https://github.com/kazu-42/calcifer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)

Calcifer is a pre-alpha, local-first Rust wrapper for running official coding-agent CLIs with isolated account profiles and usage-aware profile selection.

> [!WARNING]
> **Status: pre-alpha scaffold.** Account registration, switching, usage monitoring, and automatic failover are not implemented yet. The only implemented command is the read-only `doctor` diagnostic.

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

The bootstrap release deliberately exposes only read-only diagnostics:

```console
cargo run -- doctor
cargo run -- --json doctor
```

`doctor` checks the host and whether executables named `codex` and `claude` are discoverable on `PATH`. Name discovery does not verify their origin, version, or compatibility. The command does not execute those binaries or read or write `auth.json`, Keychain entries, provider configuration, or Calcifer state.

Example JSON envelope:

```json
{
  "schema_version": 1,
  "command": "doctor",
  "calcifer_version": "0.1.0-alpha.1",
  "ok": true,
  "status": "warn",
  "checks": []
}
```

For structured command results (currently `doctor`), `--json` emits one JSON document on stdout. Usage failures emit one redacted JSON document on stderr with exit code `2`. Clap's standard `--help` and `--version` output remains text even when `--json` is present. Within schema version 1, existing field names and meanings will remain stable; new fields may be added.

## Planned interface

The following is a design target, **not an implemented quick start**:

```console
# Register profiles through each provider's official login flow.
calcifer auth add codex work
calcifer auth add codex personal

# Select a default for future processes, or pin one invocation.
calcifer use codex work
calcifer run codex@personal -- --help

# Opt in to a bounded failover pool within one trust domain.
calcifer pool create codex personal --profiles personal-a,personal-b
calcifer run codex@personal -- --help
```

Arguments after `--` are planned as arguments to the provider adapter's validated official executable; users will not supply an arbitrary executable. The exact command surface may change before the first functional release. Unimplemented commands currently fail as unknown commands rather than pretending to succeed.

## What "automatic failover" will mean

"Token limit" can refer to different things. Calcifer's planned selection logic concerns a provider-reported usage allowance or quota window, not a model context window.

Failover will follow conservative semantics:

- It is disabled by default and limited to a user-created pool of explicitly authorized profiles.
- A pool cannot cross provider or configured trust-domain boundaries.
- Only authoritative, fresh `exhausted` state permits selecting another profile. Authentication failures, provider errors, network failures, unknown output, and stale status fail closed.
- A pool is traversed at most once per invocation and uses cooldown state to prevent loops.
- Calcifer never hot-swaps credentials in a running process.
- Calcifer never automatically replays a command or prompt under another account. A partially completed agent run may already have changed files or external systems, so replay could duplicate side effects.
- Before launch, Calcifer shows the local profile alias, provider, trust domain, and selection reason without exposing provider account identifiers.

A confirmed in-process exhaustion may influence the **next** invocation, but it will not silently restart the completed or interrupted work.

## Provider direction

| Capability | Status | Direction |
| --- | --- | --- |
| Read-only environment diagnostics | Implemented | No credential access |
| Codex profile isolation | Planned first | One `CODEX_HOME` per profile; official Codex login and refresh |
| Codex usage observation | Research/design | Structured, version-gated provider signal only |
| Opt-in profile pools | Design | Same provider and trust domain; bounded selection |
| Claude setup-token profiles | Experimental plan | OS credential store where officially supported |
| Claude subscription OAuth replication | Not planned for MVP | No undocumented OAuth endpoint or Keychain-name emulation |
| Mid-session account hot-swap or command replay | Non-goal | Unsafe side-effect semantics |

Calcifer will prefer documented provider interfaces and official CLI behavior. Provider compatibility can break when a CLI or credential format changes; unsupported or ambiguous states must stop rather than guess.

The current Linux, macOS, and Windows CI matrix covers the doctor-only scaffold. Credential management will be marked supported separately for each provider and OS only after filesystem permissions or ACLs, credential-store behavior, process supervision, and recovery paths are verified.

## Security model

Calcifer is a local profile manager and process wrapper, not a credential broker or sandbox.

Core invariants for future implementation are:

1. One process uses one immutable profile identity for its entire lifetime.
2. Calcifer never copies managed credentials into global `~/.codex` or global Claude state.
3. Only official CLI authentication and refresh mechanisms are used.
4. Secrets never enter Calcifer logs, command arguments, diagnostics, telemetry, or real test fixtures.
5. Unknown quota state and authentication errors never authorize a switch.
6. State changes are permission-checked, atomic, bounded, and recoverable.
7. Old rotated credentials are never restored over newer credentials.
8. Credential-bearing environments are passed only to the selected adapter's validated executable, never to an arbitrary user-supplied command.

File-based Codex credentials remain readable by the current OS user and the official Codex CLI; Calcifer is not an encrypted vault. Calcifer also does not sandbox the wrapped CLI, its hooks, or commands executed from the current repository.

See [Architecture](docs/architecture.md), [Security model](docs/security-model.md), and [Security policy](SECURITY.md) before contributing to authentication, storage, process execution, or failover behavior.

## Build from source

Prerequisites:

- Rust 1.85 or newer
- Git
- The official provider CLI only if you want `doctor` to detect it

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

## Development

```console
rustup toolchain install 1.85.0 --profile minimal
make fmt
make lint
make test
make check
```

The CI contract covers formatting and Clippy on Rust 1.96, tests on Linux/macOS/Windows, and an MSRV check on Rust 1.85. See [CONTRIBUTING.md](CONTRIBUTING.md) for security-sensitive review expectations.

## Roadmap

The first useful slice is Codex-only profile isolation with no shared runtime home:

1. Secure local registry and profile-name validation.
2. `calcifer auth add codex <name>` using a profile-specific `CODEX_HOME` and the official login command.
3. `calcifer run codex@<name> -- <codex arguments>` with a validated Codex executable, exact exit-code behavior, and signal forwarding.
4. Profile leases, identity verification, safe remove/re-auth flows, and redaction tests.
5. Version-gated usage observations, then explicit failover pools.
6. Claude support only through provider-supported authentication surfaces.

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
