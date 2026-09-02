.PHONY: install quickstart test verify wheel rust

install:
	python -m pip install -e '.[all]'

quickstart:
	python examples/end_to_end.py

test:
	python scripts/run_public_ci.py

verify:
	python scripts/freeze_catalog.py
	auditctl examples/payment.yaml summary
	auditvault --help

wheel:
	SOURCE_DATE_EPOCH=1704067200 python -m build --wheel

rust:
	cargo fmt --all --manifest-path rust/auditspec/Cargo.toml -- --check
	cargo test --locked --manifest-path rust/auditspec/Cargo.toml
	cargo clippy --all-targets --locked --manifest-path rust/auditspec/Cargo.toml -- -D warnings
