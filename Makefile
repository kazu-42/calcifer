PREFIX ?= $(HOME)/.local
MSRV ?= 1.85.0
SUPERVISOR_MSRV_RUNS ?= 2

.PHONY: fmt fmt-check lint test supervisor-msrv release-package-test docs msrv check install-local

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets --all-features --locked -- -D warnings

test:
	cargo test --all-targets --all-features --locked -- --test-threads=1

supervisor-msrv:
	@set -eu; \
	case "$(SUPERVISOR_MSRV_RUNS)" in \
		''|*[!0-9]*|0*) echo "SUPERVISOR_MSRV_RUNS must be a canonical positive integer" >&2; exit 2 ;; \
	esac; \
	run=1; \
	while [ "$$run" -le "$(SUPERVISOR_MSRV_RUNS)" ]; do \
		echo "Supervisor MSRV run $$run/$(SUPERVISOR_MSRV_RUNS): library unit suite"; \
		cargo +$(MSRV) test --lib --all-features --locked -- --test-threads=1; \
		echo "Supervisor MSRV run $$run/$(SUPERVISOR_MSRV_RUNS): real-exec integration matrix"; \
		cargo +$(MSRV) test --test supervisor --all-features --locked -- --test-threads=1; \
		run=$$((run + 1)); \
	done

release-package-test:
	python3 -m unittest discover -s scripts -p 'test_*.py'

docs:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked

msrv:
	cargo +$(MSRV) check --all-targets --all-features --locked

check: fmt-check lint test release-package-test docs msrv

install-local:
	cargo install --path . --locked --root "$(PREFIX)"
