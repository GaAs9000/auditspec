.PHONY: install test verify rust

install:
	python -m pip install -e '.[all]'

test:
	python scripts/run_public_ci.py

verify:
	python scripts/freeze_catalog.py
	auditctl examples/payment.yaml summary
	auditvault --help

rust:
	cargo fmt --all --manifest-path rust/auditspec/Cargo.toml -- --check
	cargo test --locked --manifest-path rust/auditspec/Cargo.toml
	cargo clippy --all-targets --locked --manifest-path rust/auditspec/Cargo.toml -- -D warnings
