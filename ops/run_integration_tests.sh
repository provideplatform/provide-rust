#!/bin/bash

#
# Copyright 2017-2022 Provide Technologies Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

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

trap handle_shutdown INT

RUN_MANY=false
if [[ $OUTPUT_DIR != "" ]]; then
    RUN_MANY=true

    DOCKER_OUTPUT=$OUTPUT_DIR/docker-output.txt
    SETUP_OUTPUT=$OUTPUT_DIR/setup-output.txt
    TEST_OUTPUT=$OUTPUT_DIR/test-output.txt
fi

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
    docker volume rm ops_prvd-baseline-db
    
    docker network rm ops_provide
    docker network rm ops_prvd-baseline

    if [[ "$INVOKE_PRVD_CLI" == "true" && ("$SUITE" == "*" || "$SUITE" == "baseline") ]]; then
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

wait_for_baseline_container() {
    baseline_status=false

    while [[ "$baseline_status" == "false" ]]; do
        baseline_status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8085/status)
        [[ "$baseline_status_code" == "204" ]] && baseline_status=true

        sleep 1
    done
    echo "baseline api container is ready"
}

# SUITE = ident, baseline, vault, etc
if [[ "$SUITE" != "" ]]; then
    echo "Running tests for $SUITE..."
    TEST=

# TEST = deploy_workflow, create_application, etc
elif [[ "$TEST" != "" ]]; then
    echo "Testing $TEST..."
    SUITE=

else
    ALL=true
    echo "No SUITE or TEST set. Running all tests..."
fi

if [[ $* == *--log-docker-info* ]]; then
    docker info
    docker network ls
fi

INVOKE_PRVD_CLI=true
if [[ $* == *--without-prvd-invocation* ]]; then
    INVOKE_PRVD_CLI=false
fi

if [[ $* == *--bounce-docker* ]]; then
    bounce_docker
fi

BASELINE_REGISTRY_CONTRACT_ADDRESS=0x
if [[ $* == *--with-registry-contract-address* ]]; then
    BASELINE_REGISTRY_CONTRACT_ADDRESS=0xCecCb4eA6B06F8990A305cafd1a9B43a9eF9c689
fi

if [[ $* != *--skip-startup* ]]; then
    # docker-compose -f ./ops/docker-compose.yml build --no-cache
    docker-compose --profile core -f ./ops/docker-compose.yml up --build -d

    if [[ $* != *--skip-baseline-startup* ]]; then
        sleep 20
        docker-compose --profile baseline -f ./ops/docker-compose.yml up --build -d
        sleep 10
    fi

    wait_for_ident_container &
    wait_for_vault_container &
    wait_for_privacy_container &
    wait_for_nchain_container &

    if [[ $* != *--skip-baseline-startup* ]]; then
        wait_for_baseline_container &
    fi
    
    wait
fi

# should selectively run this if SUITE or TEST is baseline-related, not only if --skip-setup is provided; should prolly be --with-baseline-setup flag instead anyways
if [[ $* != *--skip-setup* && "$RUN_MANY" == "true" ]]; then
    BASELINE_REGISTRY_CONTRACT_ADDRESS=$BASELINE_REGISTRY_CONTRACT_ADDRESS \
    INVOKE_PRVD_CLI=$INVOKE_PRVD_CLI \
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
    cargo nextest run --retries 3 --run-ignored ignored-only --status-level all --success-output final --failure-output final &> $SETUP_OUTPUT

elif [[ $* != *--skip-setup* ]]; then
    BASELINE_REGISTRY_CONTRACT_ADDRESS=$BASELINE_REGISTRY_CONTRACT_ADDRESS \
    INVOKE_PRVD_CLI=$INVOKE_PRVD_CLI \
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
    cargo nextest run --retries 3 --run-ignored ignored-only

fi

# TODO-- CLEANUP CODE
if [[ "$RUN_MANY" == "true" ]]; then
    if [[ "$ALL" == "true" ]]; then
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
        cargo nextest run --status-level all --no-fail-fast --success-output final --failure-output final &> $TEST_OUTPUT
    else
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
        cargo nextest run $([[ -n "$TEST" ]] && echo "$TEST" || echo --test "$SUITE") --status-level all --no-fail-fast --success-output final --failure-output final &> $TEST_OUTPUT
    fi
else
    if [[ "$ALL" == "true" ]]; then
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
        cargo nextest run --no-fail-fast --failure-output immediate-final
    else
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
        cargo nextest run $([[ -n "$TEST" ]] && echo "$TEST" || echo --test "$SUITE") --no-fail-fast --failure-output immediate-final
    fi
fi

if [[ $* != *--skip-shutdown* ]]; then
    handle_shutdown
fi

# failing ident, nchain, update config in baseline tests
# doctest ??
# cli prompt for tests with --ci flag to disable
# hide redundant stdout

# timeouts where relevant?
# adding option to handle_shutdown that only shuts down tests if --skip-shutdown wasn't provided
# --no-restart flag to take place of --skip-shutdown and --skip-restart flags
# change CONTAINER_REGEX to --log-match-pattern or something similar

# TODO-- pull latest containers