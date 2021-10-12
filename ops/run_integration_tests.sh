#!/bin/bash

docker-compose -f ./ops/docker-compose.yml build --no-cache
docker-compose -f ./ops/docker-compose.yml up -d
sleep 15
IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http VAULT_API_HOST=localhost:8082 VAULT_API_SCHEME=http PRIVACY_API_HOST=localhost:8083 PRIVACY_API_SCHEME=http cargo test -- --test-threads=1
docker-compose -f ./ops/docker-compose.yml down
docker volume rm ops_provide-db
