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

use async_trait::async_trait;

use crate::api::client::{ApiClient, Params, Response, QueryParams};
pub use crate::models::vault::*;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "vault.provide.services";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait Vault {
    fn factory(token: &str) -> Self;

    async fn create_vault(&self, params: Params) -> Response;

    async fn list_vaults(&self, query_params: QueryParams) -> Response;

    async fn create_seal_unseal_key(&self) -> Response;

    async fn unseal_vault(&self, params: Params) -> Response;

    async fn create_key(&self, vault_id: &str, params: Params) -> Response;

    async fn delete_key(&self, vault_id: &str, key_id: &str) -> Response;

    async fn derive_key(&self, vault_id: &str, key_id: &str, params: Params) -> Response;

    async fn encrypt(&self, vault_id: &str, key_id: &str, params: Params) -> Response;

    async fn decrypt(&self, vault_id: &str, key_id: &str, params: Params) -> Response;

    async fn list_keys(&self, vault_id: &str, query_params: QueryParams) -> Response;

    async fn list_secrets(&self, vault_id: &str, query_params: QueryParams) -> Response;

    async fn store_secret(&self, vault_id: &str, params: Params) -> Response;

    async fn retrieve_secret(&self, vault_id: &str, secret_id: &str, query_params: QueryParams) -> Response;

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
        return self.post("vaults", params).await;
    }

    async fn list_vaults(&self, query_params: QueryParams) -> Response {
        return self.get("vaults", query_params).await;
    }

    async fn create_seal_unseal_key(&self) -> Response {
        return self.post("unsealerkey", None).await;
    }

    async fn unseal_vault(&self, params: Params) -> Response {
        return self.post("unseal", params).await;
    }

    async fn create_key(&self, vault_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/keys", vault_id);
        return self.post(&uri, params).await;
    }

    async fn delete_key(&self, vault_id: &str, key_id: &str) -> Response {
        let uri = format!("vaults/{}/keys/{}", vault_id, key_id);
        return self.delete(&uri).await;
    }

    async fn derive_key(&self, vault_id: &str, key_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/keys/{}/derive", vault_id, key_id);
        return self.post(&uri, params).await;
    }

    async fn encrypt(&self, vault_id: &str, key_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/keys/{}/encrypt", vault_id, key_id);
        return self.post(&uri, params).await;
    }

    async fn decrypt(&self, vault_id: &str, key_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/keys/{}/encrypt", vault_id, key_id);
        return self.post(&uri, params).await;
    }

    async fn list_keys(&self, vault_id: &str, query_params: QueryParams) -> Response {
        let uri = format!("vaults/{}/keys", vault_id);
        return self.get(&uri, query_params).await;
    }

    async fn list_secrets(&self, vault_id: &str, query_params: QueryParams) -> Response {
        let uri = format!("vaults/{}/secrets", vault_id);
        return self.get(&uri, query_params).await;
    }

    async fn store_secret(&self, vault_id: &str, params: Params) -> Response {
        let uri = format!("vaults/{}/secrets", vault_id);
        return self.post(&uri, params).await;
    }

    async fn retrieve_secret(&self, vault_id: &str, secret_id: &str, query_params: QueryParams) -> Response {
        let uri = format!("vaults/{}/secrets/{}", vault_id, secret_id);
        return self.get(&uri, query_params).await;
    }

    async fn delete_secret(&self, vault_id: &str, secret_id: &str) -> Response {
        let uri = format!("vaults/{}/secrets/{}", vault_id, secret_id);
        return self.delete(&uri).await;
    }
}
