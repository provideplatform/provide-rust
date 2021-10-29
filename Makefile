.PHONY: build clean integration

clean:
	rm -rf ./target 2>/dev/null || true
	cargo clean

build: clean
	cargo fmt
	cargo build

integration:
	mode="$(MODE)" ./ops/run_integration_tests.sh
