pub use crate::client::ApiClient;
use serde::{Serialize, Deserialize};

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "ident.provide.services";
const DEFAULT_PATH: &str = "api/v1/";

pub struct Ident {
    client: ApiClient
}

// alias ie type Ident = ApiClient
// pros - doesn't wrap ApiClient into Ident struct redundancy, able to access get, post, etc methods directly
// cons - just an extension of ApiClient, not really its own Ident 'crate', doesn't scope the functions for each service to that service (ident = ident functions, vault = vault functions, etc)

// traits ie trait Ident {}, impl Ident for ApiClient
// traits seem to be more of a way to add different method functionalities, all of the same name, to a struct according to the trait that is invoked, see https://doc.rust-lang.org/rust-by-example/trait/disambiguating.html
// doesn't seem like what is required in this case, not really 'subclass' functionality

// supertraits - not trying to combine different traits at all

// associated types ie trait Ident { type ApiClient }
// again, the services are not really traits

// using mod?

impl Ident {
    // pub fn new?

    pub fn client_factory(token: String) -> Self {
        let scheme = std::env::var("IDENT_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("IDENT_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("IDENT_API_PATH").unwrap_or(String::from(DEFAULT_PATH));

        let client = ApiClient::new(scheme, host, path, token);
        Self { client }
    }

    // applications
    pub async fn create_application(&self, params: &Option<serde_json::Value>) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let res = self.client.post("applications", params).await;
        res
    }

    // pub async fn associate_user_with_application(&self, application_id: &str, application_token: &str, params: Option<serde_json::Value>) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
    //     let uri = format!("applications/{}/users", application_id);
    //     let res = self.client.post(uri,).headers(self.construct_headers()).send();
    //     res
    // }

    // pub async fn associate_user_with_application(&self, application_id: String, application_token: String, params: Option<serde_json::Value>) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
    //     let uri = format!("applications/{}/users", application_id);
    //     let res = self.post(uri, params).await?;
    //     res
    // }

    // pub async fn get_application(&self, application_id: String, params: Option<serde_json::Value>) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
    //     let uri = format!("applications/{}", application_id);
    //     let res = self.client.get(uri, params).await?;
    //     Ok( res )
    // }

    // pub async fn get_application_users(&self, application_id: String, params: Option<serde_json::Value>) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
    //     let uri = format!("applications/{}/users", application_id);
    //     let res = self.client.get(uri, params).await?;
    //     Ok( res )
    // }

    // pub async fn update_application(&self, application_id: String, params: Option<serde_json::Value>) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
    //     let uri = format!("applications/{}", application_id);
    //     let res = self.client.put(uri, params).await?;
    //     Ok( res )
    // }

    // pub async fn delete_application(&self, application_id: String, params: Option<serde_json::Value>) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
    //     let uri = format!("applications/{}", application_id);
    //     let res = self.client.delete(uri, params).await?;
    //     Ok( res )
    // }

    // organizations
    pub fn get_organizations() {}

    pub fn create_organization() {}

    pub fn get_organization() {}

    pub fn update_organization() {}

    // tokens
    pub fn get_tokens() {}

    pub fn revoke_token() {}

    pub fn authorize_long_term_token() {}

    // pub async fn authenticate(&self, params: Option<serde_json::Value>) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
    //     let res = self.client.post(String::from("authenticate"), params).await?;
    //     Ok( res )
    // }

    // users
    pub fn get_users() {}
    
    pub fn create_user() {}

    pub fn update_user() {}

    pub fn get_user() {}
    
    pub fn delete_user() {}
}

// #[derive(Copy, Clone)]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ApplicationConfig {
    network_id: Option<String>,
    baselined: Option<bool>,
    webhook_secret: String
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ident_application_suite() {
        let token = std::env::var("ACCESS_TOKEN").expect("access token");
        let ident = Ident::client_factory(token);
        let something = ident.client;

        // spin up stack locally (MAKEFILE, docker compose, ops dir), use .net, baseline, etc for reference
        // create application
        // let create_app_params = serde_json::json!({
        //     "name": "rust test application"
        // });

        // let create_app_res = ident.create_application(Some(create_app_params)).await.expect("ident create application res");
        // assert_eq!(create_app_res.status(), 201);

        // let create_app_body: Application = create_app_res.json::<Application>().await.expect("ident create application body");
        // assert_eq!(create_app_body.name, String::from("rust test application"));

        // // get applications
        // let get_apps_res = ident.get_applications(None).await.expect("ident get applications res");
        // assert_eq!(get_apps_res.status(), 200);

        // associate user with application
        // let associate_app_with_user_params = serde_json::json!({
        //     "user_id": "e82238a9-0eb7-40d9-830d-85af3f9a3832"
        // });

        // let associate_app_with_user_res = ident.associate_user_with_application(create_app_body.id, Some(associate_app_with_user_params)).await.expect("ident associate app with user res");
        
        // get application
        // let get_app_res = ident.get_application(create_app_body.clone().id, None).await.expect("ident get application res");
        // assert_eq!(get_app_res.status(), 200);

        // // get application users
        // let get_app_users_res = ident.get_application_users(create_app_body.clone().id, None).await.expect("ident get application users res");
        // assert_eq!(get_app_users_res.status(), 200);

        // // update application
        // let update_app_params = serde_json::json!({
        //     "name": "updated rust test application"
        // });

        // let update_app_res = ident.update_application(create_app_body.clone().id, Some(update_app_params)).await.expect("ident update application res");
        // assert_eq!(update_app_res.status(), 204);

        // delete application
        // let delete_app_res = ident.delete_application(create_app_body_clone_3.id, None).await.expect("ident delete application res");
        // assert_eq!(delete_app_res.status(), 204)
    }

    // #[tokio::test]
    // async fn test_ident_token_suite() {

    // }
}