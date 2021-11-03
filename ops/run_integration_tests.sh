#!/bin/bash

# handle CTRL C

# you could dump them in tmp file
dump_container_logs() {
    if [[ "$container_regex" != "" ]]; then
        echo "Dumping logs..."
        container_id=$(docker ps --filter "name=$1" | awk 'NR == 2 { print $1; exit }')
        docker logs $container_id
    fi
}

# suite = ident, baseline, vault, etc
if [[ "$suite" != "" ]]; then
    echo "Running tests for $suite..."
else
    echo "No suite set. Running all tests..."
fi

docker-compose -f ./ops/docker-compose.yml build --no-cache
docker-compose -f ./ops/docker-compose.yml up -d
sleep 20
IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http VAULT_API_HOST=localhost:8082 VAULT_API_SCHEME=http PRIVACY_API_HOST=localhost:8083 PRIVACY_API_SCHEME=http NCHAIN_API_HOST=localhost:8084 NCHAIN_API_SCHEME=http BASELINE_API_HOST=localhost:8085 BASELINE_API_SCHEME=http cargo test $suite -- --test-threads=1

# container_regex = organization-consumer, privacy, ident, etc
dump_container_logs $container_regex

docker-compose -f ./ops/docker-compose.yml down
docker volume rm ops_provide-db

if [[ "$suite" == "" || "$suite" == "baseline" ]]; then
    prvd baseline stack stop --name $(jq '.org_name' .test-config.tmp.json | xargs)
    rm .local-baseline-test-config.tmp.yaml
    rm .test-config.tmp.json
fi