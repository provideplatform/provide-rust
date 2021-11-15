pub use crate::client::{ApiClient, AdditionalHeader, Response, Params};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "vault.provide.services";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait Vault {
    fn factory(token: &str) -> Self;

    async fn create_vault(&self, params: Params) -> Response;

    async fn list_vaults(&self) -> Response;

    async fn create_seal_unseal_key(&self) -> Response;

    async fn unseal_vault(&self, params: Params) -> Response;

    async fn create_key(&self, vault_id: &str, params: Params) -> Response;

    async fn delete_key(&self, vault_id: &str, key_id: &str) -> Response;

    async fn derive_key(&self, vault_id: &str, key_id: &str, params: Params) -> Response;

    async fn encrypt(&self, vault_id: &str, key_id: &str, params: Params) -> Response;

    async fn decrypt(&self, vault_id: &str, key_id: &str, params: Params) -> Response;

    async fn list_keys(&self, vault_id: &str) -> Response;

    async fn list_secrets(&self, vault_id: &str) -> Response;

    async fn store_secret(&self, vault_id: &str, params: Params) -> Response;

    async fn retrieve_secret(&self, vault_id: &str, secret_id: &str) -> Response;

    async fn delete_secret(&self, vault_id: &str, secret_id: &str) -> Response;
}

#[async_trait]
impl Vault for ApiClient {
    fn factory(token: &str) -> Self {
        let scheme = std::env::var("VAULT_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("VAULT_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("VAULT_API_PATH").unwrap_or(String::from(DEFAULT_PATH));

        return ApiClient::new(&scheme, &host, &path, token);
    }

    async fn create_vault(&self, params: Params) -> Response {
        return self.post("vaults", params, None).await
    }

    async fn list_vaults(&self) -> Response {
        return self.get("vaults", None, None).await
    }

    async fn create_seal_unseal_key(&self) -> Response {
        return self.post("unsealerkey", None, None).await
    }

    async fn unseal_vault(&self, params: Params) -> Response {
        return self.post("unseal", params, None).await
    }

    async fn create_key(&self, vault_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/keys", vault_id);
        return self.post(&uri, params, None).await
    }

    async fn delete_key(&self, vault_id: &str, key_id: &str) -> Response {
        let uri = format!("vaults/{}/keys/{}", vault_id, key_id);
        return self.delete(&uri, None, None).await
    }

    async fn derive_key(&self, vault_id: &str, key_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/keys/{}/derive", vault_id, key_id);
        return self.post(&uri, params, None).await
    }

    async fn encrypt(&self, vault_id: &str, key_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/keys/{}/encrypt", vault_id, key_id);
        return self.post(&uri, params, None).await
    }

    async fn decrypt(&self, vault_id: &str, key_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/keys/{}/encrypt", vault_id, key_id);
        return self.post(&uri, params, None).await
    }

    async fn list_keys(&self, vault_id: &str) -> Response {
        let uri = format!("vaults/{}/keys", vault_id);
        return self.get(&uri, None, None).await
    }

    async fn list_secrets(&self, vault_id: &str) -> Response {
        let uri = format!("vaults/{}/secrets", vault_id);
        return self.get(&uri, None, None).await
    }

    async fn store_secret(&self, vault_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/secrets", vault_id);
        return self.post(&uri, params, None).await
    }

    async fn retrieve_secret(&self, vault_id: &str, secret_id: &str) -> Response {
        let uri = format!("vaults/{}/secrets/{}", vault_id, secret_id);
        return self.get(&uri, None, None).await
    }

    async fn delete_secret(&self, vault_id: &str, secret_id: &str) -> Response {
        let uri = format!("vaults/{}/secrets/{}", vault_id, secret_id);
        return self.delete(&uri, None, None).await
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VaultContainer {
    pub id: String,
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
    pub id: String,
    created_at: String,
    vault_id: String,
    r#type: String,
    usage: String,
    spec: String,
    name: String,
    description: String,
    pub address: Option<String>,
    public_key: Option<String>,
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
    use fake::Fake;
    use crate::ident::{Ident, AuthenticateResponse};
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
        let create_user_res = ident.create_user(Some(user_data)).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let params = json!({
            "email": &email,
            "password": &password,
            "scope": "offline_access",
        });
        let authenticate_res = ident.authenticate(Some(params)).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);

        return authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
    }

    async fn generate_vault(vault: &ApiClient) -> VaultContainer {
        let create_vault_params = json!({
            "name": format!("{} {}", Name().fake::<String>(), "Vault"),
            "description": "Some vault description",
        });

        let create_vault_res = vault.create_vault(Some(create_vault_params)).await.expect("create vault response");
        assert_eq!(create_vault_res.status(), 201);

        return create_vault_res.json::<VaultContainer>().await.expect("create vault response");
    }

    async fn generate_key(vault: &ApiClient, vault_id: &str) -> VaultKey {
        let create_key_params = json!({
            "type": "symmetric",
            "usage": "encrypt/decrypt",
            "spec": "ChaCha20",
            "name": Name().fake::<String>(),
            "description": "Some key description"
        });
        let create_key_res = vault.create_key(vault_id, Some(create_key_params)).await.expect("create key response");
        assert_eq!(create_key_res.status(), 201);

        return create_key_res.json::<VaultKey>().await.expect("create key response")
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

        let create_seal_unseal_key_response = vault.create_seal_unseal_key().await.expect("create seal unseal key response");
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

        let create_seal_unseal_key_response = vault.create_seal_unseal_key().await.expect("create seal unseal key response");
        assert_eq!(create_seal_unseal_key_response.status(), 201);

        let unsealer_key = create_seal_unseal_key_response.json::<UnsealerKey>().await.expect("unsealer key");

        let unseal_vault_params = json!({
            "key": unsealer_key.key,
        });
        let unseal_key_res = vault.unseal_vault(Some(unseal_vault_params)).await.expect("unseal key response");
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

        let delete_key_res = vault.delete_key(&create_vault_res.id, &create_key_res.id).await.expect("delete key response");
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

        let derive_key_res = vault.derive_key(&create_vault_res.id, &create_key_res.id, Some(derive_key_params)).await.expect("derive key response");
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

        let encrypt_res = vault.encrypt(&create_vault_res.id, &create_key_res.id, Some(encrypt_params)).await.expect("encrypt response");
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

        let encrypt_res = vault.encrypt(&create_vault_res.id, &create_key_res.id, Some(encrypt_params)).await.expect("encrypt response");
        assert_eq!(encrypt_res.status(), 200);

        let encrypt_res_body = encrypt_res.json::<EncryptedData>().await.expect("encrypted response body");
        let decrypt_params = json!({
            "data": encrypt_res_body.data,
        });

        let decrypt_res = vault.decrypt(&create_vault_res.id, &create_key_res.id, Some(decrypt_params)).await.expect("decrypt response");
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

        let list_keys_res = vault.list_keys(&create_vault_res.id).await.expect("list keys response");
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

        let list_secrets_res = vault.list_keys(&create_vault_res.id).await.expect("list secrets response");
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

        let store_secret_res = vault.store_secret(&create_vault_res.id, Some(store_secret_params)).await.expect("store secret response");
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

        let store_secret_res = vault.store_secret(&create_vault_res.id, Some(store_secret_params)).await.expect("store secret response");
        assert_eq!(store_secret_res.status(), 201);

        let store_secret_body = store_secret_res.json::<VaultSecret>().await.expect("store secret body");

        let retrieve_secret_res = vault.retrieve_secret(&create_vault_res.id, &store_secret_body.id).await.expect("retrieve secret response");
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

        let store_secret_res = vault.store_secret(&create_vault_res.id, Some(store_secret_params)).await.expect("store secret response");
        assert_eq!(store_secret_res.status(), 201);

        let store_secret_body = store_secret_res.json::<VaultSecret>().await.expect("store secret body");

        let delete_secret_res = vault.delete_secret(&create_vault_res.id, &store_secret_body.id).await.expect("delete secret response");
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