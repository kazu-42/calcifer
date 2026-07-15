# Contributing

Thank you for helping make Calcifer safer and easier to use.

## Before opening a change

Search existing issues first. Open an issue before substantial work on authentication, credential storage, identity, filesystem layout, process supervision, output parsing, quota classification, or failover behavior. Those areas change security invariants and need agreement before implementation.

Small documentation, test, and focused bug-fix pull requests can be opened directly.

## Development setup

Calcifer uses Rust 2024 and supports Rust 1.85 or newer. The repository toolchain is pinned for reproducible development.

```console
git clone https://github.com/kazu-42/calcifer.git
cd calcifer
rustup toolchain install 1.85.0 --profile minimal
make check
```

Useful commands:

```console
make fmt
make lint
make test
make supervisor-msrv
cargo run -- doctor
cargo run -- --json doctor
```

## Pull requests

Keep each pull request focused. Include:

- the user-visible problem and intended behavior;
- security and operational invariants affected by the change;
- failure modes and rollback or recovery behavior;
- tests that fail before the fix when practical;
- documentation updates for CLI or JSON contract changes;
- validation commands and their results.

Do not include real credentials, account identifiers, provider payloads, or copied production logs. Use synthetic fixtures whose values are obviously fake.

Changes to release metadata, packaging, or GitHub Actions must also follow the
[release runbook](docs/releasing.md). Release actions stay pinned by full commit
SHA, pull requests and manual runs cannot publish, and published assets are
never replaced in place.

The CI `Quality` check downloads a versioned actionlint archive, verifies its
pinned SHA-256, and lints every GitHub Actions workflow. Pull requests that
change `ci.yml`, `release.yml`, Cargo/build metadata, the `Makefile`, or release
packaging scripts also trigger the permission-minimized release validation and
native artifact matrix. Record both checks when handing off a workflow or
release-path change.

The JSON contract uses a numeric `schema_version`. Existing fields in schema version 1 cannot be removed, renamed, retyped, or assigned a different meaning. Additive fields are allowed.

## Security-sensitive changes

Changes in the following areas require explicit review against [docs/architecture.md](docs/architecture.md) and [docs/security-model.md](docs/security-model.md):

- authentication and provider adapters;
- secret storage, permissions, and atomic writes;
- identity verification or credential refresh;
- profile locking, deletion, and recovery;
- executable resolution, environment sanitation, signals, and PTYs;
- usage parsing, error classification, and automatic profile selection.

A provider or network failure must fail loudly. Do not add fallback behavior that hides partial outages, guesses an account, restores an older rotated credential, or replays a command.

## Commit and code style

Write commit messages and code comments in English. Run formatting, Clippy, tests, and the MSRV check before requesting review. New dependencies should have a clear reason, compatible license, maintained release history, and acceptable MSRV.

By contributing, you agree that your contributions are licensed under the repository's MIT License.
