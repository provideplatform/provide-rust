#!/bin/bash

if [[ "$mode" != "" ]]; then
    echo "Running tests for $mode..."
else
    echo "No mode set. Running all tests..."
fi

docker-compose -f ./ops/docker-compose.yml build --no-cache
docker-compose -f ./ops/docker-compose.yml up -d
sleep 20
IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http VAULT_API_HOST=localhost:8082 VAULT_API_SCHEME=http PRIVACY_API_HOST=localhost:8083 PRIVACY_API_SCHEME=http NCHAIN_API_HOST=localhost:8084 NCHAIN_API_SCHEME=http BASELINE_API_HOST=localhost:8085 BASELINE_API_SCHEME=http cargo test $mode -- --test-threads=1
docker-compose -f ./ops/docker-compose.yml down
docker volume rm ops_provide-db

if [[ "$mode" == "" || "$mode" == "baseline" ]]; then
    prvd baseline stack stop --name $(jq '.org_name' .test-config.json | xargs)
    rm .local-baseline-test-config.yaml
    rm .test-config.json
fi
