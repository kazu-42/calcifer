PREFIX ?= $(HOME)/.local
MSRV ?= 1.85.0

.PHONY: fmt fmt-check lint test release-package-test docs msrv check install-local

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features --locked -- -D warnings

test:
	cargo test --all-targets --all-features --locked

release-package-test:
	python3 -m unittest discover -s scripts -p 'test_*.py'

docs:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked

msrv:
	cargo +$(MSRV) check --all-targets --all-features --locked

check: fmt-check lint test release-package-test docs msrv

install-local:
	cargo install --path . --locked --root "$(PREFIX)"
