.PHONY: build clean integration baseline-integration baseline-integration-dev baseline-setup-dev

clean:
	rm -rf ./target 2>/dev/null || true
	cargo clean

build: clean
	cargo fmt
	cargo build

integration:
	SUITE="$(SUITE)" CONTAINER_REGEX="$(CONTAINER_REGEX)" ./ops/run_integration_tests.sh

baseline-integration:
	SUITE="baseline" CONTAINER_REGEX="organization-api" ./ops/run_integration_tests.sh

baseline-integration-dev:
	SUITE="baseline" ./ops/run_integration_tests.sh --without-prvd-invocation --with-registry-contract-address

baseline-setup-dev:
	SUITE="-" ./ops/run_integration_tests.sh --without-prvd-invocation --with-registry-contract-address --skip-shutdown

# TODO-- add setup cmd to setup stack w/o or running tests testing against local
# TODO-- add TEST var to run individual tests vs the entire suite