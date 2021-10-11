pub use crate::client::{ApiClient, AdditionalHeader};
use std::result::{Result};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use http;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "ident.provide.services";
const DEFAULT_PATH: &str = "api/v1";

// new fn? (as contructor)

#[async_trait]
trait Ident {
    fn factory(token: String) -> Self;
    
    async fn create_user(&self, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn authenticate(&self, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_user(&self, user_id: &str, name: &str, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_users(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn update_user(&self, user_id: &str, name: &str, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn delete_user(&self, user_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_organization(&self, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn list_organizations(&self) -> Result<reqwest::Response, reqwest::Error>;
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

    async fn get_user(&self, user_id: &str, name: &str, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("users/{}", user_id);
        let name_header = AdditionalHeader {
            key: "name",
            value: http::HeaderValue::from_str(name).expect("get user name")
        };
        return self.get(&uri, params, Some(vec!(name_header))).await
    }

    async fn get_users(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("users", &None, None).await
    }

    async fn update_user(&self, user_id: &str, name: &str, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("users/{}", user_id);
        let name_header = AdditionalHeader {
            key: "name",
            value: http::HeaderValue::from_str(name).expect("get user name")
        };
        return self.put(&uri, params, Some(vec!(name_header))).await
    }

    async fn delete_user(&self, user_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("users/{}", user_id);
        return self.delete(&uri, &None, None).await
    }

    async fn create_organization(&self, params: &Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("organizations", params, None).await
    }

    async fn list_organizations(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("organizations", &None, None).await
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
    privacy_policy_agreed_at: Option<String>,
    terms_of_service_agreed_at: Option<String>
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Token {
    id: String,
    expires_in: i32,
    token: String,
    permissions: i32
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthenticateResponse {
    user: User,
    token: Token
}

// create a new user and get token for every test

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_user() {
        let ident: ApiClient = Ident::factory("".to_string());
        let user_data = &Some(serde_json::json!({
            "first_name": "joe",
            "last_name": "dirt",
            "email": "j.d@example.org",
            "password": "joeyd12345",
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);
    }

    #[tokio::test]
    async fn authenticate() {
        let token = "".to_string();
        let ident: ApiClient = Ident::factory(token);
        let user_data = &Some(serde_json::json!({
            "first_name": "bob",
            "last_name": "thebuilder",
            "email": "bob.tb@example.org",
            "password": "buildbuild123",
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let credentials = &Some(serde_json::json!({
            "email": "bob.tb@example.org",
            "password": "buildbuild123"
        }));
        let authenticate_res = ident.authenticate(credentials).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);
    }

    #[tokio::test]
    async fn get_user() {
        let empty_token = "".to_string();
        let mut ident: ApiClient = Ident::factory(empty_token);
        let user_data = &Some(serde_json::json!({
            "first_name": "sam",
            "last_name": "iam",
            "email": "sam.theman@example.org",
            "password": "iamiamiam123",
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let credentials = &Some(serde_json::json!({
            "email": "sam.theman@example.org",
            "password": "iamiamiam123"
        }));
        let authenticate_res = ident.authenticate(credentials).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);
        
        let authenticate_res_body = authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
        let token = authenticate_res_body.token.token;
        ident.token = token;
        let get_user_res = ident.get_user(authenticate_res_body.user.id.as_str(), authenticate_res_body.user.name.as_str(), &None).await.expect("get user response");
        assert_eq!(get_user_res.status(), 200);
    }

    #[tokio::test]
    async fn list_users() {
        let empty_token = "".to_string();
        let mut ident: ApiClient = Ident::factory(empty_token);
        let user_data = &Some(serde_json::json!({
            "first_name": "van",
            "last_name": "halen",
            "email": "van.halen@example.org",
            "password": "jumppanamayay",
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let credentials = &Some(serde_json::json!({
            "email": "van.halen@example.org",
            "password": "jumppanamayay"
        }));
        let authenticate_res = ident.authenticate(credentials).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);
        
        let authenticate_res_body = authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
        let token = authenticate_res_body.token.token;
        ident.token = token;

        let get_users_res = ident.get_users().await.expect("get users response");
        assert_eq!(get_users_res.status(), 403) // FIXME
    }

    #[tokio::test]
    async fn update_user() {
        let empty_token = "".to_string();
        let mut ident: ApiClient = Ident::factory(empty_token);
        let user_data = &Some(serde_json::json!({
            "first_name": "bon",
            "last_name": "jovi",
            "email": "bon.jovi@example.org",
            "password": "runaway",
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let credentials = &Some(serde_json::json!({
            "email": "bon.jovi@example.org",
            "password": "runaway"
        }));
        let authenticate_res = ident.authenticate(credentials).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);
        
        let authenticate_res_body = authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
        let token = authenticate_res_body.token.token;
        ident.token = token;

        let update_params = &Some(serde_json::json!({
            "name": "twisted sister"
        }));
        let update_user_res = ident.update_user(authenticate_res_body.user.id.as_str(), authenticate_res_body.user.name.as_str(), update_params).await.expect("update user response");
        assert_eq!(update_user_res.status(), 204);
    }

    #[tokio::test]
    async fn delete_user() {
        let empty_token = "".to_string();
        let mut ident: ApiClient = Ident::factory(empty_token);
        let user_data = &Some(serde_json::json!({
            "first_name": "george",
            "last_name": "harrison",
            "email": "george.harrison@example.org",
            "password": "gotmymindset",
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let credentials = &Some(serde_json::json!({
            "email": "george.harrison@example.org",
            "password": "gotmymindset"
        }));
        let authenticate_res = ident.authenticate(credentials).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);
        
        let authenticate_res_body = authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
        let token = authenticate_res_body.token.token;
        ident.token = token;

        let delete_user_res = ident.delete_user(authenticate_res_body.user.id.as_str()).await.expect("delete user response");
        assert_eq!(delete_user_res.status(), 403); // FIXME
    }

    #[tokio::test]
    async fn create_organization() {
        let empty_token = "".to_string();
        let mut ident: ApiClient = Ident::factory(empty_token);
        let user_data = &Some(serde_json::json!({
            "first_name": "frank",
            "last_name": "castle",
            "email": "frank.castle@example.org",
            "password": "thepunisher",
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let credentials = &Some(serde_json::json!({
            "email": "frank.castle@example.org",
            "password": "thepunisher"
        }));
        let authenticate_res = ident.authenticate(credentials).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);
        
        let authenticate_res_body = authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
        let token = authenticate_res_body.token.token;
        ident.token = token;

        let create_organization_params = &Some(serde_json::json!({
            "name": "ACME Inc.",
            "description": "Organization for testing",
            "user_id": authenticate_res_body.user.id.as_str(),
            "metadata": {
                "hello": "world",
                "arbitrary": "input"
            }
        }));
        let create_organization_res = ident.create_organization(create_organization_params).await.expect("create organization response");
        assert_eq!(create_organization_res.status(), 201)
    }

    #[tokio::test]
    async fn list_organizations() {
        let empty_token = "".to_string();
        let mut ident: ApiClient = Ident::factory(empty_token);
        let user_data = &Some(serde_json::json!({
            "first_name": "billy",
            "last_name": "russo",
            "email": "billy.russo@example.org",
            "password": "igotkilledithink",
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let credentials = &Some(serde_json::json!({
            "email": "billy.russo@example.org",
            "password": "igotkilledithink"
        }));
        let authenticate_res = ident.authenticate(credentials).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);
        
        let authenticate_res_body = authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
        let token = authenticate_res_body.token.token;
        ident.token = token;

        let list_organizations_res = ident.list_organizations().await.expect("list organizations response");
        assert_eq!(list_organizations_res.status(), 200);
    }
}
