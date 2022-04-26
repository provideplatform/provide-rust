#!/bin/bash



echo "Running $1 tests..."
echo "Loading results into $2..."

i=0
while [[ $i -lt $1 ]]; do
    mkdir -p ~/Documents/provide-rust-runs/$i
    SUITE="baseline" CONTAINER_REGEX="organization-api" ./ops/run_integration_tests.sh ~/Documents/provide-rust-runs/$i/docker_output.txt ~/Documents/provide-rust-runs/$i/test_output.txt --with-registry-contract-address --bounce-docker
    ((i++))
done
