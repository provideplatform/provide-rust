#!/bin/bash

trap handle_shutdown INT

# you could dump them in tmp file
dump_container_logs() {
    if [[ "$CONTAINER_REGEX" != "" ]]; then
        printf "\nDumping logs...\n"
        container_id=$(docker ps --filter "name=$1" | awk 'NR == 2 { print $1; exit }')
        [[ "$container_id" != "" ]] && docker logs $container_id
    fi
}

handle_shutdown() {
    # CONTAINER_REGEX = organization-consumer, privacy-api, etc
    dump_container_logs $CONTAINER_REGEX

    docker-compose -f ./ops/docker-compose.yml down
    docker volume rm ops_provide-db

    if [[ -f ".test-config.tmp.json" ]]; then
        if [[ "$SUITE" == "" || "$SUITE" == "baseline" ]]; then
            prvd baseline stack stop --name $(jq '.org_name' .test-config.tmp.json | xargs)
            rm .local-baseline-test-config.tmp.yaml
            rm .test-config.tmp.json
        fi
    fi

    exit
}

# SUITE = ident, baseline, vault, etc
if [[ "$SUITE" != "" ]]; then
    echo "Running tests for $SUITE..."
else
    echo "No SUITE set. Running all tests..."
fi

docker-compose -f ./ops/docker-compose.yml build --no-cache
docker-compose -f ./ops/docker-compose.yml up -d
sleep 20
IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http VAULT_API_HOST=localhost:8082 VAULT_API_SCHEME=http PRIVACY_API_HOST=localhost:8083 PRIVACY_API_SCHEME=http NCHAIN_API_HOST=localhost:8084 NCHAIN_API_SCHEME=http BASELINE_API_HOST=localhost:8085 BASELINE_API_SCHEME=http cargo test $SUITE -- --test-threads=1

handle_shutdown