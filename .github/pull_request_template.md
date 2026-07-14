## What changed

Describe the focused change and the user or developer impact.

## Why

Explain the problem, relevant invariants, and why this approach fits.

## Risk and recovery

- Failure modes:
- Security or trust-boundary impact:
- Rollback or recovery:

## Validation

List the exact commands and manual checks you ran.

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --all-targets --all-features --locked`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked`
- [ ] `cargo +1.85.0 check --all-targets --all-features --locked`
- [ ] Documentation and JSON/CLI contracts are updated when applicable
- [ ] Fixtures, logs, and screenshots contain no real credentials or account identifiers
