pub use crate::client::ApiClient;
use std::result::{Result};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "ident.provide.services";
const DEFAULT_PATH: &str = "api/v1";

// new fn? (as contructor)

#[async_trait]
trait Ident {
    fn factory(token: String) -> Self;
    
    async fn create_user(&self, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn authenticate(&self, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_user(&self, user_id: &str, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;
}

#[async_trait]
impl Ident for ApiClient {
    fn factory(token: String) -> Self {
        let scheme = std::env::var("IDENT_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("IDENT_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("IDENT_API_PATH").unwrap_or(String::from(DEFAULT_PATH));

        return ApiClient::new(scheme, host, path, token);
    }

    async fn create_user(&self, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("users", params, None).await
    }

    async fn authenticate(&self, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("authenticate", params, None).await
    }

    async fn get_user(&self, user_id: &str, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("users/{}", user_id);
        // let additional_header
        return self.get(&uri, params, None).await
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ApplicationConfig {
    network_id: Option<String>,
    baselined: Option<bool>,
    webhook_secret: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Application {
    id: String,
    created_at: String,
    network_id: String,
    user_id: String,
    name: String,
    description: Option<String>,
    r#type: Option<String>,
    config: ApplicationConfig,
    hidden: bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct User {
    id: String,
    created_at: String,
    name: String,
    first_name: String,
    last_name: String,
    email: String,
    permissions: i32,
    privacy_policy_agreed_at: String,
    terms_of_service_agreed_at: String
}

// pub struct Token {
//     id: String,
//     expires_in: i32,
//     token: String,
//     permissions: i32
// }

// create a new user and get token for every test

#[cfg(test)]
mod tests {
    use super::*;

    // #[tokio::test]
    // async fn create_user() {
    //     let ident: ApiClient = Ident::factory("".to_string());

    // }

    // NEEDS TO BE A SIMPLE WAY TO CHANGE HEADERS

    #[tokio::test]
    async fn test_1() {
        // let token = std::env::var("ACCESS_TOKEN").expect("access token");
        let token = "".to_string();
        let ident: ApiClient = Ident::factory(token);
        // let get_user_res = ident.get_user("6d94e069-477a-4064-a079-fdf27225f9b6", &None).await.expect("get user response");
        // println!("{:?}", get_user_res);

        // // let get_user_body = get_user_res.json::<User>().await;
        // // println!("{:?}", get_user_body);
        // assert_eq!(get_user_res.status(), 200);

        let user_data = &Some(serde_json::json!({
            "first_name": "joe",
            "last_name": "dirt",
            "email": "j.d@example.org",
            "password": "joeyd12345",
        }));

        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);
    }
}
