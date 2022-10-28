/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use fake::faker::name::en::Name;
use fake::Fake;
use provide_rust::api::client::ApiClient;
use provide_rust::api::ident::Ident;
use provide_rust::api::nchain::*;
use serde_json::{json, Value};

mod utils;

#[tokio::test]
async fn list_accounts() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&access_token);

    let get_accounts_res = nchain
        .list_accounts(None)
        .await
        .expect("list accounts response");
    assert_eq!(
        get_accounts_res.status(),
        200,
        "get accounts response body {:?}",
        get_accounts_res.json::<Value>().await.unwrap()
    );
}

#[tokio::test]
async fn create_account() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&access_token);

    let create_account_params = Some(json!({
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
    }));

    let create_account_res = nchain
        .create_account(create_account_params)
        .await
        .expect("create account response");
    assert_eq!(
        create_account_res.status(),
        201,
        "create account response body {:?}",
        create_account_res.json::<Value>().await.unwrap()
    );
}

#[tokio::test]
async fn get_account() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&access_token);

    let create_account_params = Some(json!({
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
    }));

    let create_account_res = nchain
        .create_account(create_account_params)
        .await
        .expect("create account response");
    assert_eq!(create_account_res.status(), 201);

    let create_account_body = create_account_res
        .json::<Account>()
        .await
        .expect("create account body");

    let get_account_res = nchain
        .get_account(&create_account_body.id, None)
        .await
        .expect("get account response");
    assert_eq!(get_account_res.status(), 200);
}

#[tokio::test]
async fn get_connectors() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let application_auth_body =
        utils::generate_application_auth(&ident, &create_application_body.id).await;

    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&application_access_token);

    let get_connectors_res = nchain
        .list_connectors(None)
        .await
        .expect("get connectors response");
    assert_eq!(get_connectors_res.status(), 200);
}

#[tokio::test]
async fn create_connector() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let application_auth_body =
        utils::generate_application_auth(&ident, &create_application_body.id).await;

    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&application_access_token);

    let create_connector_params = Some(json!({
        "application_id": create_application_body.id,
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
        "name": format!("{} {}", Name().fake::<String>(), "Connector"),
        "type": "provide",
        "config": {
            "api_port": 8080,
            "api_url": "https://ceeb3bca-3b92-44b9-8ac5-fdd4564-717022042.us-east-2.elb.amazonaws.com:8080",
            "container": "providenetwork-ipfs",
            "image": "provide/ident",
            "provider_id": "docker",
            "region": "us-east-2",
            "role": "peer",
            "target_id": "aws"
        },
    }));

    let create_connector_res = nchain
        .create_connector(create_connector_params)
        .await
        .expect("create connector response");
    assert_eq!(create_connector_res.status(), 201);
}

#[tokio::test]
async fn get_connector() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let application_auth_body =
        utils::generate_application_auth(&ident, &create_application_body.id).await;

    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&application_access_token);

    let create_connector_params = Some(json!({
        "application_id": create_application_body.id,
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
        "name": format!("{} {}", Name().fake::<String>(), "Connector"),
        "type": "provide",
        "config": {
            "api_port": 8080,
            "api_url": "https://ceeb3bca-3b92-44b9-8ac5-fdd4564-717022042.us-east-2.elb.amazonaws.com:8080",
            "container": "providenetwork-ipfs",
            "image": "provide/ident",
            "provider_id": "docker",
            "region": "us-east-2",
            "role": "peer",
            "target_id": "aws"
        },
    }));

    let create_connector_res = nchain
        .create_connector(create_connector_params)
        .await
        .expect("create connector response");
    assert_eq!(create_connector_res.status(), 201);

    let create_connector_body = create_connector_res
        .json::<Connector>()
        .await
        .expect("create connector body");

    let get_connector_res = nchain
        .get_connector(&create_connector_body.id, None)
        .await
        .expect("get connector response");
    assert_eq!(get_connector_res.status(), 200);
}

#[tokio::test]
async fn delete_connector() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let application_auth_body =
        utils::generate_application_auth(&ident, &create_application_body.id).await;

    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&application_access_token);

    let create_connector_params = Some(json!({
        "application_id": create_application_body.id,
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
        "name": format!("{} {}", Name().fake::<String>(), "Connector"),
        "type": "provide",
        "config": {
            "api_port": 8080,
            "api_url": "https://ceeb3bca-3b92-44b9-8ac5-fdd4564-717022042.us-east-2.elb.amazonaws.com:8080",
            "container": "providenetwork-ipfs",
            "image": "provide/ident",
            "provider_id": "docker",
            "region": "us-east-2",
            "role": "peer",
            "target_id": "aws"
        },
    }));

    let create_connector_res = nchain
        .create_connector(create_connector_params)
        .await
        .expect("create connector response");
    assert_eq!(create_connector_res.status(), 201);

    let create_connector_body = create_connector_res
        .json::<Connector>()
        .await
        .expect("create connector body");

    let delete_connector_res = nchain
        .delete_connector(&create_connector_body.id)
        .await
        .expect("delete connector res");
    assert_eq!(delete_connector_res.status(), 500); // FIXME
}

#[tokio::test]
async fn list_contracts() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let application_auth_body =
        utils::generate_application_auth(&ident, &create_application_body.id).await;

    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&application_access_token);

    let get_contracts_res = nchain
        .list_contracts(None)
        .await
        .expect("get contracts response");
    assert_eq!(get_contracts_res.status(), 200);
}

#[tokio::test]
async fn create_contract() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let application_auth_body =
        utils::generate_application_auth(&ident, &create_application_body.id).await;

    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&application_access_token);

    let create_contract_params = Some(json!({
        "application_id": &create_application_body.id,
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
        "name": format!("{} {}", Name().fake::<String>(), "Contract"),
        "address": "0x"
    }));

    let create_contract_res = nchain
        .create_contract(create_contract_params)
        .await
        .expect("create contract response");
    assert_eq!(create_contract_res.status(), 201);
}

#[tokio::test]
async fn get_contract() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let application_auth_body =
        utils::generate_application_auth(&ident, &create_application_body.id).await;

    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&application_access_token);

    let create_contract_params = Some(json!({
        "application_id": &create_application_body.id,
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
        "name": format!("{} {}", Name().fake::<String>(), "Contract"),
        "address": "0x"
    }));

    let create_contract_res = nchain
        .create_contract(create_contract_params)
        .await
        .expect("create contract response");
    assert_eq!(create_contract_res.status(), 201);

    let create_contract_body = create_contract_res
        .json::<Contract>()
        .await
        .expect("create contract body");

    let get_contract_res = nchain
        .get_contract(&create_contract_body.id, None)
        .await
        .expect("get contract response");
    assert_eq!(get_contract_res.status(), 200);
}

#[tokio::test]
async fn execute_contract() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let application_auth_body =
        utils::generate_application_auth(&ident, &create_application_body.id).await;

    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&application_access_token);

    let create_contract_params = Some(json!({
        "application_id": &create_application_body.id,
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
        "name": format!("{} {}", Name().fake::<String>(), "Contract"),
        "address": "0x"
    }));

    let create_contract_res = nchain
        .create_contract(create_contract_params)
        .await
        .expect("create contract response");
    assert_eq!(create_contract_res.status(), 201);

    let create_contract_body = create_contract_res
        .json::<Contract>()
        .await
        .expect("create contract body");

    let create_wallet_params = Some(json!({
        "application_id": &create_application_body.id,
    }));

    let create_wallet_res = nchain
        .create_wallet(create_wallet_params)
        .await
        .expect("create wallet response");
    assert_eq!(create_wallet_res.status(), 201);

    let create_wallet_body = create_wallet_res
        .json::<Wallet>()
        .await
        .expect("create wallet body");

    let execute_contract_params = Some(json!({
        "value": 0,
        "wallet_id": create_wallet_body.id,
    }));

    let execute_contract_res = nchain
        .execute_contract(&create_contract_body.id, execute_contract_params)
        .await
        .expect("execute contract response");
    assert_eq!(execute_contract_res.status(), 202);
}

#[tokio::test]
async fn get_wallets() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&access_token);

    let get_wallets_res = nchain
        .list_wallets(None)
        .await
        .expect("get wallets response");
    assert_eq!(get_wallets_res.status(), 200);
}

#[tokio::test]
async fn create_wallet() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&access_token);

    let create_wallet_params = Some(json!({
        "user_id": authentication_res_body.user.id,
    }));

    let create_wallet_res = nchain
        .create_wallet(create_wallet_params)
        .await
        .expect("create wallet response");
    assert_eq!(create_wallet_res.status(), 201);
}

#[tokio::test]
async fn get_wallet_accounts() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&access_token);

    let create_wallet_params = Some(json!({
        "user_id": authentication_res_body.user.id,
    }));

    let create_wallet_res = nchain
        .create_wallet(create_wallet_params)
        .await
        .expect("create wallet response");
    assert_eq!(create_wallet_res.status(), 201);

    let create_wallet_body = create_wallet_res
        .json::<Wallet>()
        .await
        .expect("create wallet body");

    let get_wallet_accounts_res = nchain
        .list_wallet_accounts(&create_wallet_body.id, None)
        .await
        .expect("get wallet accounts response");
    assert_eq!(get_wallet_accounts_res.status(), 200);
}

#[tokio::test]
async fn get_networks() {
    // org access token is the only one that returns globally enabled networks
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_organization_body =
        utils::generate_organization(&ident, &authentication_res_body.user.id).await;

    let organization_auth_body =
        utils::generate_organization_auth(&ident, &create_organization_body.id).await;

    let organization_access_token = match organization_auth_body.access_token {
        Some(string) => string,
        None => panic!(
            "organization authentication response access token not found {:?}",
            organization_auth_body
        ),
    };

    let nchain: ApiClient = NChain::factory(&organization_access_token);

    let get_networks_res = nchain
        .list_networks(None)
        .await
        .expect("get networks response");
    assert_eq!(get_networks_res.status(), 200);

    let get_networks_body = get_networks_res
        .json::<Vec<Network>>()
        .await
        .expect("get networks body");
    assert!(
        get_networks_body.len() == 0,
        "get networks body length: {}",
        get_networks_body.len()
    );
}

#[tokio::test]
async fn create_network() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let application_auth_body =
        utils::generate_application_auth(&ident, &create_application_body.id).await;

    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&application_access_token);

    let create_network_params = Some(json!({
        "Application_id": &create_application_body.id,
        "name": format!("{} {}", Name().fake::<String>(), "Network"),
        "enabled": true,
        "chain_id": "0x1618585621",
        "config": {
            "chain": "test",
            "chainspec": {
                "alloc": {},
                "coinbase": 0,
                "config": {
                    "byzantiumBlock": 0,
                    "constantinopleBlock": 0,
                    "eip150Block": 0,
                    "eip155Block": 0,
                    "eip158Block": 0,
                    "homesteadBlock": 0,
                    "petersburgBlock": 0
                },
                "difficulty": 131072,
                "extraData": "",
                "gasLimit": 3141592,
                "mixhash": 0,
                "nonce": 66,
                "parentHash": 0,
                "timestamp": 0
            },
            "engine_id": "ethash",
            "native_currency": "TEST",
            "network_id": 1618585621,
            "platform": "evm",
            "layer2": false,
            "protocol_id": "pow"
        },
        "layer2": false,
    }));

    let create_network_res = nchain
        .create_network(create_network_params)
        .await
        .expect("create network response");
    assert_eq!(
        create_network_res.status(),
        201,
        "create network res: {}",
        serde_json::to_string_pretty(
            &create_network_res
                .json::<serde_json::Value>()
                .await
                .unwrap()
        )
        .unwrap()
    );
}

#[tokio::test]
async fn update_network() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let nchain: ApiClient = NChain::factory(&access_token);

    let create_network_params = Some(json!({
        "application_id": &create_application_body.id,
        "name": format!("{} {}", Name().fake::<String>(), "Network"),
        "enabled": true,
        "chain_id": "0x1618585621",
        "config": {
            "chain": "test",
            "chainspec": {
                "alloc": {},
                "coinbase": 0,
                "config": {
                    "byzantiumBlock": 0,
                    "constantinopleBlock": 0,
                    "eip150Block": 0,
                    "eip155Block": 0,
                    "eip158Block": 0,
                    "homesteadBlock": 0,
                    "petersburgBlock": 0
                },
                "difficulty": 131072,
                "extraData": "",
                "gasLimit": 3141592,
                "mixhash": 0,
                "nonce": 66,
                "parentHash": 0,
                "timestamp": 0
            },
            "engine_id": "ethash",
            "native_currency": "TEST",
            "network_id": 1618585621,
            "platform": "evm",
            "layer2": false,
            "protocol_id": "pow"
        },
        "layer2": false,
    }));

    let create_network_res = nchain
        .create_network(create_network_params)
        .await
        .expect("create network response");
    assert_eq!(
        create_network_res.status(),
        201,
        "create network res: {}",
        serde_json::to_string_pretty(
            &create_network_res
                .json::<serde_json::Value>()
                .await
                .unwrap()
        )
        .unwrap()
    );

    let create_network_body = create_network_res
        .json::<Network>()
        .await
        .expect("create network body");

    let update_network_params = Some(json!({
        "description": "some network description"
    }));

    let update_network_res = nchain
        .update_network(&create_network_body.id, update_network_params)
        .await
        .expect("udpate network response");
    assert_eq!(update_network_res.status(), 204);
}

#[tokio::test]
async fn get_network() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        utils::generate_application(&ident, &authentication_res_body.user.id).await;

    let nchain: ApiClient = NChain::factory(&access_token);

    let create_network_params = Some(json!({
        "application_id": &create_application_body.id,
        "name": format!("{} {}", Name().fake::<String>(), "Network"),
        "enabled": true,
        "chain_id": "0x1618585621",
        "config": {
            "chain": "test",
            "chainspec": {
                "alloc": {},
                "coinbase": 0,
                "config": {
                    "byzantiumBlock": 0,
                    "constantinopleBlock": 0,
                    "eip150Block": 0,
                    "eip155Block": 0,
                    "eip158Block": 0,
                    "homesteadBlock": 0,
                    "petersburgBlock": 0
                },
                "difficulty": 131072,
                "extraData": "",
                "gasLimit": 3141592,
                "mixhash": 0,
                "nonce": 66,
                "parentHash": 0,
                "timestamp": 0
            },
            "engine_id": "ethash",
            "native_currency": "TEST",
            "network_id": 1618585621,
            "platform": "evm",
            "layer2": false,
            "protocol_id": "pow"
        },
        "layer2": false,
    }));

    let create_network_res = nchain
        .create_network(create_network_params)
        .await
        .expect("create network response");
    assert_eq!(create_network_res.status(), 201);

    let create_network_body = create_network_res
        .json::<Network>()
        .await
        .expect("create network body");

    let get_network_res = nchain
        .get_network(&create_network_body.id, None)
        .await
        .expect("get network response");
    assert_eq!(get_network_res.status(), 200);
}

// #[tokio::test]
// async fn get_oracles() {
//     let authentication_res_body = utils::generate_user_and_token().await;
//     let access_token = match authentication_res_body.token.access_token {
//         Some(string) => string,
//         None => panic!("authentication response access token not found"),
//     };

//     let nchain: ApiClient = NChain::factory(&access_token);

//     let get_oracles_res = nchain.get_oracles().await.expect("get oracles response");
//     assert_eq!(get_oracles_res.status(), 200);
// }

#[tokio::test]
async fn get_transactions() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&access_token);

    let get_transactions_res = nchain
        .list_transactions(None)
        .await
        .expect("get transactions response");
    assert_eq!(get_transactions_res.status(), 200);
}

#[tokio::test]
async fn create_transaction() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&access_token);

    let create_wallet_params = Some(json!({
        "user_id": authentication_res_body.user.id,
    }));

    let create_wallet_res = nchain
        .create_wallet(create_wallet_params)
        .await
        .expect("create wallet response");
    assert_eq!(create_wallet_res.status(), 201);

    let create_wallet_body = create_wallet_res
        .json::<Wallet>()
        .await
        .expect("create wallet body");

    let create_transaction_params = Some(json!({
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
        "user_id": &authentication_res_body.user.id,
        "wallet_id": &create_wallet_body.id,
        "hd_derivation_path": "m/44'/60'/0'/0/0",
        "to": "7c8fe6f1-38c3-4da1-b4b7-7591c6d0ca7c",
        "value": 0
    }));

    let create_transaction_res = nchain
        .create_transaction(create_transaction_params)
        .await
        .expect("create transaction response");
    assert_eq!(create_transaction_res.status(), 201);
}

#[tokio::test]
async fn get_transaction() {
    let authentication_res_body = utils::generate_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let nchain: ApiClient = NChain::factory(&access_token);

    let create_wallet_params = Some(json!({
        "user_id": authentication_res_body.user.id,
    }));

    let create_wallet_res = nchain
        .create_wallet(create_wallet_params)
        .await
        .expect("create wallet response");
    assert_eq!(create_wallet_res.status(), 201);

    let create_wallet_body = create_wallet_res
        .json::<Wallet>()
        .await
        .expect("create wallet body");

    let create_transaction_params = Some(json!({
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
        "user_id": &authentication_res_body.user.id,
        "wallet_id": &create_wallet_body.id,
        "hd_derivation_path": "m/44'/60'/0'/0/0",
        "to": "7c8fe6f1-38c3-4da1-b4b7-7591c6d0ca7c",
        "value": 0
    }));

    let create_transaction_res = nchain
        .create_transaction(create_transaction_params)
        .await
        .expect("create transaction response");
    assert_eq!(create_transaction_res.status(), 201);

    let create_transaction_body = create_transaction_res
        .json::<Transaction>()
        .await
        .expect("create transaction body");

    let get_transaction_res = nchain
        .get_transaction(&create_transaction_body.id, None)
        .await
        .expect("get transaction response");
    assert_eq!(get_transaction_res.status(), 200);
}

// ONLY USE GET IN PLACE OF RETRIEVE, LIST, etc
// for structs with org and app id they should both prolly be option
// could consider 'nicer' naming ie list_multiple, get_single_detail, more deploy
// load balancer details call?

// how to add the comments that show on hover in vscode ie in TS it is @param, @return in /** **/ block

// make them non optional
