#!/bin/bash

if [[ $# != 1 ]]; then
    echo "must pass desired number of test runs"
    exit 0
fi

echo "Running $1 tests..."

i=0
while [[ $i -lt $1 ]]; do
    mkdir -p test-output/$i
    SUITE="baseline" CONTAINER_REGEX="organization-api" OUTPUT_DIR="test-output/$i" ./ops/run_integration_tests.sh --with-registry-contract-address
    ((i++))
done
