.PHONY: build clean integration baseline-integration

clean:
	rm -rf ./target 2>/dev/null || true
	cargo clean

build: clean
	cargo fmt
	cargo build

integration:
	SUITE="$(SUITE)" CONTAINER_REGEX="$(CONTAINER_REGEX)" ./ops/run_integration_tests.sh

baseline-integration:
	SUITE="baseline" CONTAINER_REGEX="organization-api" ./ops/run_integration_tests.sh --log-docker-networks