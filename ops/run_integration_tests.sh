#!/bin/bash

trap handle_shutdown INT

# WARNING-- the bounce_docker command below will do some potentially unwanted
# things in your local environment!!!
#
# This command requires the docker daemon to be running... if it is not running
# or for some reason docker is not installed or not available on your PATH,
# this command will exit with a non-zero status.
#
# 1. All your running containers, if any, will be killed
# 2. All your docker networks, if any, will be pruned
# 3. All your docker volumes, if any, will be pruned
# 4. The docker daemon itself will be gracefully restarted
#
# Why is this needed here?! (Keep reading...)
#
# This is here to workaround a strange issue related to the docker network
# stack that intermittently causes the simulated test suite to hang, causing
# massive frustration for users! For some months, it has been a misconception
# that the BRI-1 stack is "unstable" for example, because numerous developers
# were unable to successfully run the environment consistently. This is a workaround
# we have come across that will prevent us from needing to investigate docker
# itself... we will however provide some additional details on the issue
# and a few links to others reporting similar behavior. After the docker daemon
# starts, the network stack plays nicely... until it doesn't. Then the simulation,
# which demonstrates the Provide production stack in the context of a a multi-network
# multi-party workflow across the private network of each party and the WAN for
# workflow state synchronization...
#
# Some liquor has now been poured out at this juncture to commemorate the
# sanity and endurance of one Lucas Rodriguez, who investigated this issue :D
#
# Additional notes:
#
# This has been tested exclusively on the following operating systems and Docker versions:
#   - MacOS 12.0.1 with Apple Silicon
#   - Docker v4.3.2 (72729).
#
# YMMV! Would love to hear what OS/version and Docker version others are running
# and if this workaround consistently helps them run the simulation, which turns
# out to be quite robust! :D
#
# Ahhhh... software! ....... 0_o
bounce_docker() {
    # FIXME-- make sure $(which docker) is a thing...

    $(docker kill $(docker ps -q)) &2>/dev/null
    $(docker rm $(docker ps -a -q)) &2>/dev/null
    $(docker network prune -f) &2>/dev/null
    $(docker volume prune -f) &2>/dev/null

    # alternatively... the following might be a little nicer...
    # docker system prune 2>/dev/null
}

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

    if [[ "$INVOKE_PRVD_CLI" == "true" && ("$SUITE" == "" || "$SUITE" == "baseline") ]]; then
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

if [[ $* == *--log-docker-info* ]]; then
    docker info
    docker network ls
fi

INVOKE_PRVD_CLI=true
if [[ $* == *--without-prvd-invocation* ]]; then
    INVOKE_PRVD_CLI=false
fi

if [[ "$INVOKE_PRVD_CLI" == "true" ]]; then
    bounce_docker
fi

BASELINE_REGISTRY_CONTRACT_ADDRESS=
if [[ $* == *--with-registry-contract-address* ]]; then
    BASELINE_REGISTRY_CONTRACT_ADDRESS=0xCecCb4eA6B06F8990A305cafd1a9B43a9eF9c689
fi

# docker-compose -f ./ops/docker-compose.yml build --no-cache
docker-compose -f ./ops/docker-compose.yml up --build -d

wait_for_ident_container
wait_for_vault_container
wait_for_privacy_container
wait_for_nchain_container

BASELINE_REGISTRY_CONTRACT_ADDRESS=$BASELINE_REGISTRY_CONTRACT_ADDRESS \
IDENT_API_HOST=localhost:8081 \
IDENT_API_SCHEME=http \
VAULT_API_HOST=localhost:8082 \
VAULT_API_SCHEME=http \
PRIVACY_API_HOST=localhost:8083 \
PRIVACY_API_SCHEME=http \
NCHAIN_API_HOST=localhost:8084 \
NCHAIN_API_SCHEME=http \
BASELINE_API_HOST=localhost:8085 \
BASELINE_API_SCHEME=http \
INVOKE_PRVD_CLI=$INVOKE_PRVD_CLI \
cargo test one -- --test-threads=1 --show-output

handle_shutdown

# parallel flag