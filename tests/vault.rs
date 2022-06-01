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
use provide_rust::api::ident::{AuthenticateResponse, Ident};
use provide_rust::api::vault::*;
use serde_json::json;

async fn generate_new_user_and_token() -> AuthenticateResponse {
    let ident: ApiClient = Ident::factory("");

    let email = FreeEmail().fake::<String>();
    let password = Password(8..15).fake::<String>();

    let user_data = json!({
        "first_name": FirstName().fake::<String>(),
        "last_name": LastName().fake::<String>(),
        "email": &email,
        "password": &password,
    });
    let create_user_res = ident
        .create_user(Some(user_data))
        .await
        .expect("create user response");
    assert_eq!(create_user_res.status(), 201);

    let params = json!({
        "email": &email,
        "password": &password,
        "scope": "offline_access",
    });
    let authenticate_res = ident
        .authenticate(Some(params))
        .await
        .expect("authenticate response");
    assert_eq!(authenticate_res.status(), 201);

    return authenticate_res
        .json::<AuthenticateResponse>()
        .await
        .expect("authentication response body");
}

async fn generate_vault(vault: &ApiClient) -> VaultContainer {
    let create_vault_params = json!({
        "name": format!("{} {}", Name().fake::<String>(), "Vault"),
        "description": "Some vault description",
    });

    let create_vault_res = vault
        .create_vault(Some(create_vault_params))
        .await
        .expect("create vault response");
    assert_eq!(create_vault_res.status(), 201);

    return create_vault_res
        .json::<VaultContainer>()
        .await
        .expect("create vault response");
}

async fn generate_key(vault: &ApiClient, vault_id: &str) -> VaultKey {
    let create_key_params = json!({
        "type": "symmetric",
        "usage": "encrypt/decrypt",
        "spec": "ChaCha20",
        "name": Name().fake::<String>(),
        "description": "Some key description"
    });
    let create_key_res = vault
        .create_key(vault_id, Some(create_key_params))
        .await
        .expect("create key response");
    assert_eq!(create_key_res.status(), 201);

    return create_key_res
        .json::<VaultKey>()
        .await
        .expect("create key response");
}

#[tokio::test]
async fn create_vault() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let _ = generate_vault(&vault);
}

#[tokio::test]
async fn list_vaults() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let list_vaults_response = vault.list_vaults().await.expect("list vaults response");
    assert_eq!(list_vaults_response.status(), 200);
}

#[tokio::test]
async fn create_seal_unseal_key() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_seal_unseal_key_response = vault
        .create_seal_unseal_key()
        .await
        .expect("create seal unseal key response");
    assert_eq!(create_seal_unseal_key_response.status(), 201);
}

#[tokio::test]
async fn unseal_vault() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_seal_unseal_key_response = vault
        .create_seal_unseal_key()
        .await
        .expect("create seal unseal key response");
    assert_eq!(create_seal_unseal_key_response.status(), 201);

    let unsealer_key = create_seal_unseal_key_response
        .json::<UnsealerKey>()
        .await
        .expect("unsealer key");

    let unseal_vault_params = json!({
        "key": unsealer_key.key,
    });
    let unseal_key_res = vault
        .unseal_vault(Some(unseal_vault_params))
        .await
        .expect("unseal key response");
    assert_eq!(unseal_key_res.status(), 204);
}

#[tokio::test]
async fn create_key() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;

    let _ = generate_key(&vault, &create_vault_res.id);
}

#[tokio::test]
async fn delete_key() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;
    let create_key_res = generate_key(&vault, &create_vault_res.id).await;

    let delete_key_res = vault
        .delete_key(&create_vault_res.id, &create_key_res.id)
        .await
        .expect("delete key response");
    assert_eq!(delete_key_res.status(), 204);
}

#[tokio::test]
async fn derive_key() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;
    let create_key_res = generate_key(&vault, &create_vault_res.id).await;
    let derive_key_params = json!({
        "nonce": 2,
        "context": "provide rust testing",
        "name": Name().fake::<String>(),
        "description": "Some derive key description",
    });

    let derive_key_res = vault
        .derive_key(
            &create_vault_res.id,
            &create_key_res.id,
            Some(derive_key_params),
        )
        .await
        .expect("derive key response");
    assert_eq!(derive_key_res.status(), 201);
}

#[tokio::test]
async fn encrypt() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;
    let create_key_res = generate_key(&vault, &create_vault_res.id).await;
    let encrypt_params = json!({
        "data": "some data",
    });

    let encrypt_res = vault
        .encrypt(
            &create_vault_res.id,
            &create_key_res.id,
            Some(encrypt_params),
        )
        .await
        .expect("encrypt response");
    assert_eq!(encrypt_res.status(), 200);
}

#[tokio::test]
async fn decrypt() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;
    let create_key_res = generate_key(&vault, &create_vault_res.id).await;
    let encrypt_params = json!({
        "data": "some data",
    });

    let encrypt_res = vault
        .encrypt(
            &create_vault_res.id,
            &create_key_res.id,
            Some(encrypt_params),
        )
        .await
        .expect("encrypt response");
    assert_eq!(encrypt_res.status(), 200);

    let encrypt_res_body = encrypt_res
        .json::<EncryptedData>()
        .await
        .expect("encrypted response body");
    let decrypt_params = json!({
        "data": encrypt_res_body.data,
    });

    let decrypt_res = vault
        .decrypt(
            &create_vault_res.id,
            &create_key_res.id,
            Some(decrypt_params),
        )
        .await
        .expect("decrypt response");
    assert_eq!(decrypt_res.status(), 200);
}

#[tokio::test]
async fn list_users() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;

    let list_keys_res = vault
        .list_keys(&create_vault_res.id)
        .await
        .expect("list keys response");
    assert_eq!(list_keys_res.status(), 200);
}

#[tokio::test]
async fn list_secrets() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;

    let list_secrets_res = vault
        .list_keys(&create_vault_res.id)
        .await
        .expect("list secrets response");
    assert_eq!(list_secrets_res.status(), 200);
}

#[tokio::test]
async fn store_secret() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;

    let store_secret_params = json!({
        "type": "sample secret",
        "name": Name().fake::<String>(),
        "description": "this secret is being stored for demonstration purposes",
        "value": "0x",
    });

    let store_secret_res = vault
        .store_secret(&create_vault_res.id, Some(store_secret_params))
        .await
        .expect("store secret response");
    assert_eq!(store_secret_res.status(), 201);
}

#[tokio::test]
async fn retrieve_secret() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;

    let store_secret_params = json!({
        "type": "sample secret",
        "name": Name().fake::<String>(),
        "description": "this secret is being stored for demonstration purposes",
        "value": "0x",
    });

    let store_secret_res = vault
        .store_secret(&create_vault_res.id, Some(store_secret_params))
        .await
        .expect("store secret response");
    assert_eq!(store_secret_res.status(), 201);

    let store_secret_body = store_secret_res
        .json::<VaultSecret>()
        .await
        .expect("store secret body");

    let retrieve_secret_res = vault
        .retrieve_secret(&create_vault_res.id, &store_secret_body.id)
        .await
        .expect("retrieve secret response");
    assert_eq!(retrieve_secret_res.status(), 200);
}

#[tokio::test]
async fn delete_secret() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let vault: ApiClient = Vault::factory(&access_token);

    let create_vault_res = generate_vault(&vault).await;

    let store_secret_params = json!({
        "type": "sample secret",
        "name": Name().fake::<String>(),
        "description": "this secret is being stored for demonstration purposes",
        "value": "0x",
    });

    let store_secret_res = vault
        .store_secret(&create_vault_res.id, Some(store_secret_params))
        .await
        .expect("store secret response");
    assert_eq!(store_secret_res.status(), 201);

    let store_secret_body = store_secret_res
        .json::<VaultSecret>()
        .await
        .expect("store secret body");

    let delete_secret_res = vault
        .delete_secret(&create_vault_res.id, &store_secret_body.id)
        .await
        .expect("delete secret response");
    assert_eq!(delete_secret_res.status(), 204);
}

// keys
//  create key
//  delete key
//  derive key
//  encrypt
//  decrypt
//  list keys

// secrets
//  list secrets
//  store secret
//  retrieve secret
//  delete secret

// create vault
// list vaults
// create seal/unseal key
// unseal vault

// TODO
// rename VaultKey, VaultSecret to Key, Secret, etc
