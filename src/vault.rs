pub use crate::client::{ApiClient, AdditionalHeader};
use std::result::{Result};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
// use http;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "vault.provide.services";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait Vault {
    fn factory(token: String) -> Self;

    async fn create_vault(&self, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn list_vaults(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_seal_unseal_key(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn unseal_vault(&self, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_key(&self, vault_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn delete_key(&self, vault_id: &str, key_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn derive_key(&self, vault_id: &str, key_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn encrypt(&self, vault_id: &str, key_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn decrypt(&self, vault_id: &str, key_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn list_keys(&self, vault_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn list_secrets(&self, vault_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn store_secret(&self, vault_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn retrieve_secret(&self, vault_id: &str, secret_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn delete_secret(&self, vault_id: &str, secret_id: &str) -> Result<reqwest::Response, reqwest::Error>;
}

#[async_trait]
impl Vault for ApiClient {
    fn factory(token: String) -> Self {
        let scheme = std::env::var("VAULT_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("VAULT_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("VAULT_API_PATH").unwrap_or(String::from(DEFAULT_PATH));

        return ApiClient::new(scheme, host, path, token);
    }

    async fn create_vault(&self, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("vaults", params, None).await
    }

    async fn list_vaults(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("vaults", None, None).await
    }

    async fn create_seal_unseal_key(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("unsealerkey", None, None).await
    }

    async fn unseal_vault(&self, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("unseal", params, None).await
    }

    async fn create_key(&self, vault_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/keys", vault_id);
        return self.post(&uri, params, None).await
    }

    async fn delete_key(&self, vault_id: &str, key_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/keys/{}", vault_id, key_id);
        return self.delete(&uri, None, None).await
    }

    async fn derive_key(&self, vault_id: &str, key_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/keys/{}/derive", vault_id, key_id);
        return self.post(&uri, params, None).await
    }

    async fn encrypt(&self, vault_id: &str, key_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/keys/{}/encrypt", vault_id, key_id);
        return self.post(&uri, params, None).await
    }

    async fn decrypt(&self, vault_id: &str, key_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/keys/{}/encrypt", vault_id, key_id);
        return self.post(&uri, params, None).await
    }

    async fn list_keys(&self, vault_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/keys", vault_id);
        return self.get(&uri, None, None).await
    }

    async fn list_secrets(&self, vault_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/secrets", vault_id);
        return self.get(&uri, None, None).await
    }

    async fn store_secret(&self, vault_id: &str, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/secrets", vault_id);
        return self.post(&uri, params, None).await
    }

    async fn retrieve_secret(&self, vault_id: &str, secret_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/secrets/{}", vault_id, secret_id);
        return self.get(&uri, None, None).await
    }

    async fn delete_secret(&self, vault_id: &str, secret_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("vaults/{}/secrets/{}", vault_id, secret_id);
        return self.delete(&uri, None, None).await
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VaultContainer {
    id: String,
    created_at: String,
    name: String,
    description: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct UnsealerKey {
    key: String,
    validation_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VaultKey {
    id: String,
    created_at: String,
    vault_id: String,
    r#type: String,
    usage: String,
    spec: String,
    name: String,
    description: String
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct EncryptedData {
    data: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VaultSecret {
    id: String,
    created_at: String,
    vault_id: String,
    r#type: String,
    name: String,
    description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::name::en::{Name, FirstName, LastName};
    use fake::faker::internet::en::{FreeEmail, Password};
    use fake::{Fake};
    pub use crate::ident::{Ident, AuthenticateResponse};

    async fn generate_new_user_and_token() -> AuthenticateResponse {
        let ident: ApiClient = Ident::factory("".to_string());

        let email = FreeEmail().fake::<String>();
        let password = Password(std::ops::Range { start: 8, end: 15 }).fake::<String>();

        let user_data = Some(serde_json::json!({
            "first_name": FirstName().fake::<String>(),
            "last_name": LastName().fake::<String>(),
            "email": &email,
            "password": &password,
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let credentials = Some(serde_json::json!({
            "email": &email,
            "password": &password,
        }));
        let authenticate_res = ident.authenticate(credentials).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);

        return authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
    }

    async fn generate_vault(vault: &ApiClient) -> VaultContainer {
        let create_vault_params = Some(serde_json::json!({
            "name": format!("{} {}", Name().fake::<String>(), "Vault"),
            "description": "Some vault description",
        }));

        let create_vault_res = vault.create_vault(create_vault_params).await.expect("create vault response");
        assert_eq!(create_vault_res.status(), 201);

        return create_vault_res.json::<VaultContainer>().await.expect("create vault response");
    }

    async fn generate_key(vault: &ApiClient, vault_id: &str) -> VaultKey {
        let create_key_params = Some(serde_json::json!({
            "type": "symmetric",
            "usage": "encrypt/decrypt",
            "spec": "ChaCha20",
            "name": Name().fake::<String>(),
            "description": "Some key description"
        }));
        let create_key_res = vault.create_key(vault_id, create_key_params).await.expect("create key response");
        assert_eq!(create_key_res.status(), 201);

        return create_key_res.json::<VaultKey>().await.expect("create key response")
    }

    #[tokio::test]
    async fn create_vault() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let _ = generate_vault(&vault);
    }

    #[tokio::test]
    async fn list_vaults() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let list_vaults_response = vault.list_vaults().await.expect("list vaults response");
        assert_eq!(list_vaults_response.status(), 200);
    }

    #[tokio::test]
    async fn create_seal_unseal_key() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_seal_unseal_key_response = vault.create_seal_unseal_key().await.expect("create seal unseal key response");
        assert_eq!(create_seal_unseal_key_response.status(), 201);
    }

    #[tokio::test]
    async fn unseal_vault() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_seal_unseal_key_response = vault.create_seal_unseal_key().await.expect("create seal unseal key response");
        assert_eq!(create_seal_unseal_key_response.status(), 201);

        let unsealer_key = create_seal_unseal_key_response.json::<UnsealerKey>().await.expect("unsealer key");

        let unseal_vault_params = Some(serde_json::json!({
            "key": unsealer_key.key,
        }));
        let unseal_key_res = vault.unseal_vault(unseal_vault_params).await.expect("unseal key response");
        assert_eq!(unseal_key_res.status(), 204);
    }

    #[tokio::test]
    async fn create_key() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;

        let _ = generate_key(&vault, create_vault_res.id.as_str());
    }

    #[tokio::test]
    async fn delete_key() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;
        let create_key_res = generate_key(&vault, create_vault_res.id.as_str()).await;

        let delete_key_res = vault.delete_key(create_vault_res.id.as_str(), create_key_res.id.as_str()).await.expect("delete key response");
        assert_eq!(delete_key_res.status(), 204);
    }

    #[tokio::test]
    async fn derive_key() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;
        let create_key_res = generate_key(&vault, create_vault_res.id.as_str()).await;
        let derive_key_params = Some(serde_json::json!({
            "nonce": 2,
            "context": "provide rust testing",
            "name": Name().fake::<String>(),
            "description": "Some derive key description",
        }));

        let derive_key_res = vault.derive_key(create_vault_res.id.as_str(), create_key_res.id.as_str(), derive_key_params).await.expect("derive key response");
        assert_eq!(derive_key_res.status(), 201);
    }

    #[tokio::test]
    async fn encrypt() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;
        let create_key_res = generate_key(&vault, create_vault_res.id.as_str()).await;
        let encrypt_params = Some(serde_json::json!({
            "data": "some data",
        }));

        let encrypt_res = vault.encrypt(create_vault_res.id.as_str(), create_key_res.id.as_str(), encrypt_params).await.expect("encrypt response");
        assert_eq!(encrypt_res.status(), 200);
    }

    #[tokio::test]
    async fn decrypt() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;
        let create_key_res = generate_key(&vault, create_vault_res.id.as_str()).await;
        let encrypt_params = Some(serde_json::json!({
            "data": "some data",
        }));

        let encrypt_res = vault.encrypt(create_vault_res.id.as_str(), create_key_res.id.as_str(), encrypt_params).await.expect("encrypt response");
        assert_eq!(encrypt_res.status(), 200);

        let encrypt_res_body = encrypt_res.json::<EncryptedData>().await.expect("encrypted response body");
        let decrypt_params = Some(serde_json::json!({
            "data": encrypt_res_body.data,
        }));

        let decrypt_res = vault.decrypt(create_vault_res.id.as_str(), create_key_res.id.as_str(), decrypt_params).await.expect("decrypt response");
        assert_eq!(decrypt_res.status(), 200);
    }

    #[tokio::test]
    async fn list_users() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;

        let list_keys_res = vault.list_keys(create_vault_res.id.as_str()).await.expect("list keys response");
        assert_eq!(list_keys_res.status(), 200);
    }

    #[tokio::test]
    async fn list_secrets() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;

        let list_secrets_res = vault.list_keys(create_vault_res.id.as_str()).await.expect("list secrets response");
        assert_eq!(list_secrets_res.status(), 200);
    }

    #[tokio::test]
    async fn store_secret() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;

        let store_secret_params = Some(serde_json::json!({
            "type": "sample secret",
            "name": Name().fake::<String>(),
            "description": "this secret is being stored for demonstration purposes",
            "value": "0x",
        }));

        let store_secret_res = vault.store_secret(create_vault_res.id.as_str(), store_secret_params).await.expect("store secret response");
        assert_eq!(store_secret_res.status(), 201);
    }

    #[tokio::test]
    async fn retrieve_secret() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;

        let store_secret_params = Some(serde_json::json!({
            "type": "sample secret",
            "name": Name().fake::<String>(),
            "description": "this secret is being stored for demonstration purposes",
            "value": "0x",
        }));

        let store_secret_res = vault.store_secret(create_vault_res.id.as_str(), store_secret_params).await.expect("store secret response");
        assert_eq!(store_secret_res.status(), 201);

        let store_secret_body = store_secret_res.json::<VaultSecret>().await.expect("store secret body");

        let retrieve_secret_res = vault.retrieve_secret(create_vault_res.id.as_str(), store_secret_body.id.as_str()).await.expect("retrieve secret response");
        assert_eq!(retrieve_secret_res.status(), 200);
    }

    #[tokio::test]
    async fn delete_secret() {
        let authentication_res_body = generate_new_user_and_token().await;
        let vault: ApiClient = Vault::factory(authentication_res_body.token.token);

        let create_vault_res = generate_vault(&vault).await;

        let store_secret_params = Some(serde_json::json!({
            "type": "sample secret",
            "name": Name().fake::<String>(),
            "description": "this secret is being stored for demonstration purposes",
            "value": "0x",
        }));

        let store_secret_res = vault.store_secret(create_vault_res.id.as_str(), store_secret_params).await.expect("store secret response");
        assert_eq!(store_secret_res.status(), 201);

        let store_secret_body = store_secret_res.json::<VaultSecret>().await.expect("store secret body");

        let delete_secret_res = vault.delete_secret(create_vault_res.id.as_str(), store_secret_body.id.as_str()).await.expect("delete secret response");
        assert_eq!(delete_secret_res.status(), 204);
    }
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