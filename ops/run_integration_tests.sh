#!/bin/bash

trap handle_shutdown INT

# could dump logs into tmp file
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

    if [[ "$SUITE" == "" || "$SUITE" == "baseline" ]]; then
        if [[ -f ".test-config.tmp.json" ]]; then
            prvd baseline stack stop --name $(jq '.org_name' .test-config.tmp.json | xargs)
            rm .local-baseline-test-config.tmp.yaml
            rm .test-config.tmp.json
        fi
    fi

    exit
}

wait_for_ident_container() {
    ident_status=false

    while [[ "$ident_status" == "false" ]]; do
        ident_status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/status)
        [[ "$ident_status_code" == "200" ]] && ident_status=true

        sleep 1
    done
    echo "ident api container is ready"
}

wait_for_vault_container() {
    vault_status=false

    while [[ "$vault_status" == "false" ]]; do
        vault_status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8082/status)
        [[ "$vault_status_code" == "204" ]] && vault_status=true

        sleep 1
    done
    echo "vault api container is ready"
}

wait_for_privacy_container() {
    privacy_status=false

    while [[ "$privacy_status" == "false" ]]; do
        privacy_status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8083/status)
        [[ "$privacy_status_code" == "204" ]] && privacy_status=true

        sleep 1
    done
    echo "privacy api container is ready"

}

wait_for_nchain_container() {
    nchain_status=false

    while [[ "$nchain_status" == "false" ]]; do
        nchain_status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8084/status)
        [[ "$nchain_status_code" == "204" ]] && nchain_status=true

        sleep 1
    done
    echo "nchain api container is ready"
}

# SUITE = ident, baseline, vault, etc
if [[ "$SUITE" != "" ]]; then
    echo "Running tests for $SUITE..."
else
    echo "No SUITE set. Running all tests..."
fi

if [[ $* == *--log-docker-networks* ]]; then
    echo "docker networks on init"
    docker network ls
fi

wait_for_ident_container &
wait_for_vault_container &
wait_for_privacy_container &
wait_for_nchain_container &

docker-compose -f ./ops/docker-compose.yml build --no-cache &
docker-compose -f ./ops/docker-compose.yml up -d &
wait

# if [[ $* == *--log-docker-networks* ]]; then
#     echo "docker networks pre setup"
#     docker network ls
# fi

IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http VAULT_API_HOST=localhost:8082 VAULT_API_SCHEME=http PRIVACY_API_HOST=localhost:8083 PRIVACY_API_SCHEME=http NCHAIN_API_HOST=localhost:8084 NCHAIN_API_SCHEME=http BASELINE_API_HOST=localhost:8085 BASELINE_API_SCHEME=http cargo test $SUITE -- --test-threads=1

handle_shutdown