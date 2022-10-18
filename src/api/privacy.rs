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

use crate::api::client::{ApiClient, Params, Response};
pub use crate::models::privacy::*;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "privacy.provide.services";
const DEFAULT_PATH: &str = "api/v1";

pub const PREIMAGE_HASH_IDENTIFIER: &str = "preimage_hash";
pub const BLS12_377_CURVE: &str = "BLS12_377";
pub const GNARK_PROVIDER: &str = "gnark";
pub const GROTH16_PROVING_SCHEME: &str = "groth16";

#[async_trait]
pub trait Privacy {
    fn factory(token: &str) -> Self;

    async fn list_provers(&self) -> Response;

    async fn create_prover(&self, params: Params) -> Response;

    async fn get_prover(&self, prover_id: &str) -> Response;

    async fn generate_proof(&self, prover_id: &str, params: Params) -> Response;

    async fn verify_proof(&self, prover_id: &str, params: Params) -> Response;

    async fn retrieve_store_value(&self, prover_id: &str, leaf_index: &str) -> Response;
}

#[async_trait]
impl Privacy for ApiClient {
    fn factory(token: &str) -> Self {
        let scheme = std::env::var("PRIVACY_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("PRIVACY_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("PRIVACY_API_PATH").unwrap_or(String::from(DEFAULT_PATH));

        return ApiClient::new(&scheme, &host, &path, token);
    }

    async fn list_provers(&self) -> Response {
        return self.get("provers", None, None, None).await;
    }

    async fn create_prover(&self, params: Params) -> Response {
        return self.post("provers", params, None).await;
    }

    async fn get_prover(&self, prover_id: &str) -> Response {
        let uri = format!("provers/{}", prover_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn generate_proof(&self, prover_id: &str, params: Params) -> Response {
        let uri = format!("provers/{}/prove", prover_id);
        return self.post(&uri, params, None).await;
    }

    async fn verify_proof(&self, prover_id: &str, params: Params) -> Response {
        let uri = format!("provers/{}/verify", prover_id);
        return self.post(&uri, params, None).await;
    }

    async fn retrieve_store_value(&self, prover_id: &str, leaf_index: &str) -> Response {
        let uri = format!("provers/{}/notes/{}", prover_id, leaf_index);
        return self.get(&uri, None, None, None).await;
    }
}
