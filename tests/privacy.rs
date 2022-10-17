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

use fake::faker::internet::en::{FreeEmail, Password};
use fake::faker::name::en::{FirstName, LastName, Name};
use fake::Fake;
use provide_rust::api::client::ApiClient;
use provide_rust::api::ident::{Application, AuthenticateResponse, Ident, Token};
use provide_rust::api::nchain::ROPSTEN_TESTNET_NETWORK_ID;
use provide_rust::api::privacy::*;
use serde_json::json;
use tokio::time::{self, Duration};

async fn generate_new_user_and_token() -> AuthenticateResponse {
    let ident: ApiClient = Ident::factory("");

    let email = FreeEmail().fake::<String>();
    let password = Password(8..15).fake::<String>();

    let user_data = Some(json!({
        "first_name": FirstName().fake::<String>(),
        "last_name": LastName().fake::<String>(),
        "email": &email,
        "password": &password,
    }));
    let create_user_res = ident
        .create_user(user_data)
        .await
        .expect("create user response");
    assert_eq!(create_user_res.status(), 201);

    let params = Some(json!({
        "email": &email,
        "password": &password,
        "scope": "offline_access",
    }));
    let authenticate_res = ident
        .authenticate(params)
        .await
        .expect("authenticate response");
    assert_eq!(authenticate_res.status(), 201);

    return authenticate_res
        .json::<AuthenticateResponse>()
        .await
        .expect("authentication response body");
}

async fn deploy_prover(privacy: &ApiClient) -> Prover {
    let create_prover_params = Some(json!({
        "name": Name().fake::<String>(),
        "identifier": "cubic",
        "provider": "gnark",
        "proving_scheme": "groth16",
        "curve": "BN254",
    }));

    let create_prover_res = privacy
        .create_prover(create_prover_params)
        .await
        .expect("create prover response");
    assert_eq!(create_prover_res.status(), 201);

    return create_prover_res
        .json::<Prover>()
        .await
        .expect("create prover body");
}

#[tokio::test]
async fn list_provers() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let privacy: ApiClient = Privacy::factory(&access_token);

    let list_provers_res = privacy.list_provers().await.expect("list provers response");
    assert_eq!(list_provers_res.status(), 200);
}

#[tokio::test]
async fn create_prover() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let privacy: ApiClient = Privacy::factory(&access_token);
    let _ = deploy_prover(&privacy).await;
}

#[tokio::test]
async fn get_prover() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let privacy: ApiClient = Privacy::factory(&access_token);
    let deploy_prover_body = deploy_prover(&privacy).await;

    let get_prover_res = privacy
        .get_prover(&deploy_prover_body.id)
        .await
        .expect("get prover response");
    assert_eq!(get_prover_res.status(), 200);
}

#[tokio::test]
async fn generate_proof() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let application_data = Some(json!({
        "network_id": ROPSTEN_TESTNET_NETWORK_ID,
        "user_id": authentication_res_body.user.id,
        "name": format!("{} {}", Name().fake::<String>(), "Application"),
        "description": "Some application description",
        "type": "baseline",
        "hidden": false
    }));

    let create_application_res = ident
        .create_application(application_data)
        .await
        .expect("generate application response");
    assert_eq!(create_application_res.status(), 201);

    let create_application_body = create_application_res
        .json::<Application>()
        .await
        .expect("create application body");
    let application_auth_params = Some(json!({
        "application_id": create_application_body.id,
        "scope": "offline_access",
    }));

    let application_auth_res = ident
        .application_authorization(application_auth_params)
        .await
        .expect("application authorization response");

    let application_auth_body = application_auth_res
        .json::<Token>()
        .await
        .expect("application authorization body");
    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let privacy: ApiClient = Privacy::factory(&application_access_token);

    let deploy_prover_body = deploy_prover(&privacy).await;

    let mut interval = time::interval(Duration::from_millis(500));
    let mut prover_status = match deploy_prover_body.status {
        Some(string) => string,
        None => panic!("deploy prover status not found"),
    };

    while prover_status != "provisioned" {
        interval.tick().await;

        let get_prover_res = privacy
            .get_prover(&deploy_prover_body.id)
            .await
            .expect("get prover response");
        assert_eq!(get_prover_res.status(), 200);

        let get_prover_body = get_prover_res
            .json::<Prover>()
            .await
            .expect("get prover body");
        prover_status = match get_prover_body.status {
            Some(string) => string,
            None => panic!("get prover body status not found"),
        };
    }

    let generate_proof_param = Some(json!({
        "identifier": deploy_prover_body.identifier,
        "proving_scheme": "groth16",
        "curve": "BN254",
        "provider": "gnark",
        "name": deploy_prover_body.name,
        "store_id": deploy_prover_body.note_store_id,
        "witness": {
            "X": "3",
            "Y": "35",
        }
    }));

    let generate_proof_res = privacy
        .generate_proof(&deploy_prover_body.id, generate_proof_param)
        .await
        .expect("generate proof response");
    assert_eq!(generate_proof_res.status(), 200);
}

#[tokio::test]
async fn verify_proof() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let application_data = Some(json!({
        "network_id": ROPSTEN_TESTNET_NETWORK_ID,
        "user_id": authentication_res_body.user.id,
        "name": format!("{} {}", Name().fake::<String>(), "Application"),
        "description": "Some application description",
        "type": "baseline",
        "hidden": false
    }));

    let create_application_res = ident
        .create_application(application_data)
        .await
        .expect("generate application response");
    assert_eq!(create_application_res.status(), 201);

    let create_application_body = create_application_res
        .json::<Application>()
        .await
        .expect("create application body");
    let application_auth_params = Some(json!({
        "application_id": create_application_body.id,
        "scope": "offline_access",
    }));

    let application_auth_res = ident
        .application_authorization(application_auth_params)
        .await
        .expect("application authorization response");

    let application_auth_body = application_auth_res
        .json::<Token>()
        .await
        .expect("application authorization body");
    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let privacy: ApiClient = Privacy::factory(&application_access_token);

    let deploy_prover_body = deploy_prover(&privacy).await;

    let mut interval = time::interval(Duration::from_millis(500));
    let mut prover_status = match deploy_prover_body.status {
        Some(string) => string,
        None => panic!("deploy prover status not found"),
    };

    while prover_status != "provisioned" {
        interval.tick().await;

        let get_prover_res = privacy
            .get_prover(&deploy_prover_body.id)
            .await
            .expect("get prover response");
        assert_eq!(get_prover_res.status(), 200);

        let get_prover_body = get_prover_res
            .json::<Prover>()
            .await
            .expect("get prover body");
        prover_status = match get_prover_body.status {
            Some(string) => string,
            None => panic!("get prover body status not found"),
        };
    }

    let generate_proof_param = Some(json!({
        "identifier": deploy_prover_body.identifier,
        "proving_scheme": "groth16",
        "curve": "BN254",
        "provider": "gnark",
        "name": deploy_prover_body.name,
        "store_id": deploy_prover_body.note_store_id,
        "witness": {
            "X": "3",
            "Y": "35",
        },
    }));

    let generate_proof_res = privacy
        .generate_proof(&deploy_prover_body.id, generate_proof_param)
        .await
        .expect("generate proof response");
    assert_eq!(generate_proof_res.status(), 200);

    let create_proof_body = generate_proof_res
        .json::<Proof>()
        .await
        .expect("create proof body");

    let verify_proof_params = Some(json!({
        "witness": {
            "X": "3",
            "Y": "35",
        },
        "proof": create_proof_body.proof,
    }));

    let verify_proof_res = privacy
        .verify_proof(&deploy_prover_body.id, verify_proof_params)
        .await
        .expect("verify proof response");
    assert_eq!(verify_proof_res.status(), 200);
}

#[tokio::test]
async fn retrieve_store_value() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let application_data = Some(json!({
        "network_id": ROPSTEN_TESTNET_NETWORK_ID,
        "user_id": authentication_res_body.user.id,
        "name": format!("{} {}", Name().fake::<String>(), "Application"),
        "description": "Some application description",
        "type": "baseline",
        "hidden": false
    }));

    let create_application_res = ident
        .create_application(application_data)
        .await
        .expect("generate application response");
    assert_eq!(create_application_res.status(), 201);

    let create_application_body = create_application_res
        .json::<Application>()
        .await
        .expect("create application body");
    let application_auth_params = Some(json!({
        "application_id": create_application_body.id,
        "scope": "offline_access",
    }));

    let application_auth_res = ident
        .application_authorization(application_auth_params)
        .await
        .expect("application authorization response");

    let application_auth_body = application_auth_res
        .json::<Token>()
        .await
        .expect("application authorization body");
    let application_access_token = match application_auth_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };

    let privacy: ApiClient = Privacy::factory(&application_access_token);

    let deploy_prover_body = deploy_prover(&privacy).await;

    let mut interval = time::interval(Duration::from_millis(500));
    let mut prover_status = match deploy_prover_body.status {
        Some(string) => string,
        None => panic!("deploy prover status not found"),
    };

    while prover_status != "provisioned" {
        interval.tick().await;

        let get_prover_res = privacy
            .get_prover(&deploy_prover_body.id)
            .await
            .expect("get prover response");
        assert_eq!(get_prover_res.status(), 200);

        let get_prover_body = get_prover_res
            .json::<Prover>()
            .await
            .expect("get prover body");
        prover_status = match get_prover_body.status {
            Some(string) => string,
            None => panic!("get prover body status not found"),
        };
    }

    let generate_proof_param = Some(json!({
        "identifier": deploy_prover_body.identifier,
        "proving_scheme": "groth16",
        "curve": "BN254",
        "provider": "gnark",
        "name": deploy_prover_body.name,
        "store_id": deploy_prover_body.note_store_id,
        "witness": {
            "X": "3",
            "Y": "35",
        },
    }));

    let generate_proof_res = privacy
        .generate_proof(&deploy_prover_body.id, generate_proof_param)
        .await
        .expect("generate proof response");
    assert_eq!(generate_proof_res.status(), 200);

    let retrieve_store_value_res = privacy
        .retrieve_store_value(&deploy_prover_body.id, "0")
        .await
        .expect("retrieve store value response");
    assert_eq!(retrieve_store_value_res.status(), 200);
}
