.PHONY: build clean integration baseline-integration

clean:
	rm -rf ./target 2>/dev/null || true
	cargo clean

build: clean
	cargo fmt
	cargo build

integration:
	suite="$(SUITE)" container_regex="$(CONTAINER_REGEX)" ./ops/run_integration_tests.sh

baseline-integration:
	suite="baseline" container_regex="organization-api" ./ops/run_integration_tests.sh