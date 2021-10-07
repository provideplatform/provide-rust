pub use crate::client::ApiClient;
use serde::{Serialize, Deserialize};

pub struct Ident {
    pub client: ApiClient
}

#[derive(Serialize, Deserialize)]
pub struct ApplicationConfig {
    network_id: Option<String>,
    baselined: Option<bool>,
    webhook_secret: String
}

#[derive(Serialize, Deserialize)]
pub struct Application {
    id: String,
    created_at: String,
    network_id: String,
    user_id: String,
    name: String,
    description: Option<String>,
    r#type: Option<String>,
    config: ApplicationConfig,
    hidden: bool
}

// pub struct User {
//     id: String,
//     created_at: String,
//     name: String,
//     first_name: String,
//     last_name: String,
//     email: String,
//     permissions: i32,
//     privacy_policy_agreed_at: String,
//     terms_of_service_agreed_at: String
// }

// pub struct Token {
//     id: String,
//     expires_in: i32,
//     token: String,
//     permissions: i32
// }

impl Ident {
    pub fn init(scheme: Option<String>, host: Option<String>, token: Option<String>) -> Result<Self, ()> {
        let _scheme = scheme.unwrap_or(String::from("https"));
        let _host = host.unwrap_or(String::from("ident.provide.services"));

        let client = ApiClient::init(Some(_scheme), Some(_host), Some(String::from("api/v1")), token).expect("ident api client");
        Ok( Self { client } )
    }

    // applications
    pub async fn create_application(&self, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let res = self.client.post(String::from("applications"), params).await?;
        Ok( res )
    }

    pub async fn get_applications(&self, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let res = self.client.get(String::from("applications"), params).await?;
        Ok( res )
    }
    
    pub async fn associate_user_with_application(&self, application_id: String, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}/users", application_id);
        let res = self.client.post(uri, params).await?;
        Ok ( res )
    }

    pub async fn get_application(&self, application_id: String, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}", application_id);
        let res = self.client.get(uri, params).await?;
        Ok( res )
    }

    pub fn get_application_users() {}

    pub async fn update_application(&self, application_id: String, params: serde_json::Value) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}", application_id);
        let res = self.client.put(uri, params).await?;
        Ok( res )
    }

    pub fn delete_application() {}

    // organizations
    pub fn get_organizations() {}

    pub fn create_organization() {}

    pub fn get_organization() {}

    pub fn update_organization() {}

    // tokens
    pub fn get_tokens() {}

    pub fn revoke_token() {}

    pub fn authorize_long_term_token() {}

    pub async fn authenticate(&self, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let res = self.client.post(String::from("authenticate"), params).await?;
        Ok( res )
    }

    // users
    pub fn get_users() {}
    
    pub fn create_user() {}

    pub fn update_user() {}

    pub fn get_user() {}
    
    pub fn delete_user() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ident_client_init() {
        let ident = Ident::init(None, None, Some(String::from(""))).expect("ident client");

        assert_eq!(ident.client.base_url, String::from("https://ident.provide.services/api/v1"))
    }

    #[tokio::test]
    async fn test_ident_application_suite() {
        let token = std::env::var("ACCESS_TOKEN").expect("access token");
        let ident = Ident::init(None, None, Some(token)).expect("ident application client");

        // create application
        let create_app_params = serde_json::json!({
            "name": "rust test application"
        });

        let create_app_res = ident.create_application(Some(create_app_params)).await.expect("ident create application res");
        assert_eq!(create_app_res.status(), 201);

        let create_app_body: Application = create_app_res.json::<Application>().await.expect("ident create application body");
        assert_eq!(create_app_body.name, String::from("rust test application"));

        // get applications
        let get_apps_res = ident.get_applications(None).await.expect("ident get applications res");
        assert_eq!(get_apps_res.status(), 200);

        // associate user with application
        let associate_app_with_user_params = serde_json::json!({
            "user_id": create_app_body.user_id
        });

        let associate_app_with_user_res = ident.associate_user_with_application(create_app_body.id, Some(associate_app_with_user_params)).await.expect("ident associate app with user res");
        

    }

    // #[tokio::test]
    // async fn test_ident_token_suite() {

    // }
}