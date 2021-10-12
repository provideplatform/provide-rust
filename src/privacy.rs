pub use crate::client::{ApiClient, AdditionalHeader};
use std::result::{Result};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use serde_json::{Value};
use http::HeaderValue;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "privacy.provide.services";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait Privacy {
    fn factory(token: String) -> Self;

    async fn list_circuits(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_circuit(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_circuit(&self, circuit_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn prove_circuit(&self, circuit_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn verify(&self, circuit_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn retrieve_store_value(&self, circuit_id: &str, leaf_index: &str) -> Result<reqwest::Response, reqwest::Error>;
}

#[async_trait]
impl Privacy for ApiClient {
    fn factory(token: String) -> Self {
        let scheme = std::env::var("PRIVACY_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("PRIVACY_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("PRIVACY_API_PATH").unwrap_or(String::from(DEFAULT_PATH));
    
        return ApiClient::new(scheme, host, path, token);
    }

    async fn list_circuits(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("circuits", None, None).await
    }

    async fn create_circuit(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("circuits", params, None).await
    }

    async fn get_circuit(&self, circuit_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("circuits/{}", circuit_id);
        return self.get(&uri, None, None).await
    }

    async fn prove_circuit(&self, circuit_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("circuits/{}/prove", circuit_id);
        return self.post(&uri, params, None).await
    }

    async fn verify(&self, circuit_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("circuits/{}/verify", circuit_id);
        return self.post(&uri, params, None).await
    }

    async fn retrieve_store_value(&self, circuit_id: &str, leaf_index: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("circuits/{}/store/{}", circuit_id, leaf_index);
        return self.get(&uri, None, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::name::en::{Name, FirstName, LastName};
    use fake::faker::internet::en::{FreeEmail, Password};
    use fake::{Fake};
    use crate::ident::{Ident, AuthenticateResponse};
    use serde_json::json;

    async fn generate_new_user_and_token() -> AuthenticateResponse {
        let ident: ApiClient = Ident::factory("".to_string());

        let email = FreeEmail().fake::<String>();
        let password = Password(8..15).fake::<String>();

        let user_data = Some(json!({
            "first_name": FirstName().fake::<String>(),
            "last_name": LastName().fake::<String>(),
            "email": &email,
            "password": &password,
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let params = Some(json!({
            "email": &email,
            "password": &password,
            "scope": "offline_access",
        }));
        let authenticate_res = ident.authenticate(params).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);

        return authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
    }

    #[tokio::test]
    async fn list_circuits() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let privacy: ApiClient = Privacy::factory(access_token);

        let list_circuits_res = privacy.list_circuits().await.expect("list circuits response");
        assert_eq!(list_circuits_res.status(), 200);
    }
}