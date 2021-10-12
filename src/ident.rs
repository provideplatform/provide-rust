pub use crate::client::{ApiClient, AdditionalHeader};
use std::result::{Result};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use serde_json::{Value};
use http::HeaderValue;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "ident.provide.services";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait Ident {
    fn factory(token: String) -> Self;
    
    async fn create_user(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_user(&self, user_id: &str, name: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_users(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn update_user(&self, user_id: &str, name: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn delete_user(&self, user_id: &str) -> Result<reqwest::Response, reqwest::Error>;
    
    async fn authenticate(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn application_authorization(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn organization_authorization(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;
    
    async fn list_tokens(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn revoke_token(&self, token_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_organization(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_organization(&self, organization_id: &str) -> Result<reqwest::Response, reqwest::Error>;
    
    async fn list_organizations(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn update_organization(&self, organization_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_application(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;
    
    async fn get_application(&self, application_id: &str) -> Result<reqwest::Response, reqwest::Error>;
    
    async fn list_applications(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn update_application(&self, application_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn delete_application(&self, application_id: &str)  -> Result<reqwest::Response, reqwest::Error>;
    
    async fn list_application_users(&self, application_id: &str)  -> Result<reqwest::Response, reqwest::Error>;

    async fn associate_application_user(&self, application_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;
}

#[async_trait]
impl Ident for ApiClient {
    fn factory(token: String) -> Self {
        let scheme = std::env::var("IDENT_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("IDENT_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("IDENT_API_PATH").unwrap_or(String::from(DEFAULT_PATH));

        return ApiClient::new(scheme, host, path, token);
    }

    async fn create_user(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("users", params, None).await
    }

    async fn authenticate(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("authenticate", params, None).await
    }

    async fn get_user(&self, user_id: &str, name: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("users/{}", user_id);
        let name_header = AdditionalHeader {
            key: "name",
            value: HeaderValue::from_str(name).expect("get user name")
        };
        return self.get(&uri, params, Some(vec!(name_header))).await
    }

    async fn get_users(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("users", None, None).await
    }

    async fn update_user(&self, user_id: &str, name: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("users/{}", user_id);
        let name_header = AdditionalHeader {
            key: "name",
            value: HeaderValue::from_str(name).expect("get user name")
        };
        return self.put(&uri, params, Some(vec!(name_header))).await
    }

    async fn delete_user(&self, user_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("users/{}", user_id);
        return self.delete(&uri, None, None).await
    }

    async fn create_organization(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("organizations", params, None).await
    }

    async fn list_organizations(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("organizations", None, None).await
    }

    async fn get_organization(&self, organization_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("organizations/{}", organization_id);
        return self.get(&uri, None, None).await
    }

    async fn update_organization(&self, organization_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("organizations/{}", organization_id);
        return self.put(&uri, params, None).await
    }

    async fn application_authorization(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("tokens", params, None).await
    }

    async fn organization_authorization(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("tokens", params, None).await
    }

    async fn list_tokens(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("tokens", params, None).await
    }

    async fn list_applications(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("applications", None, None).await
    }

    async fn create_application(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("applications", params, None).await
    }

    async fn get_application(&self, application_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}", application_id);
        return self.get(&uri, None, None).await
    }

    async fn update_application(&self, application_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}", application_id);
        return self.put(&uri, params, None).await
    }

    async fn list_application_users(&self, application_id: &str)  -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}/users", application_id);
        return self.get(&uri, None, None).await
    }

    async fn delete_application(&self, application_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}", application_id);
        return self.delete(&uri, None, None).await
    }

    async fn associate_application_user(&self, application_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}/users", application_id);
        return self.post(&uri, params, None).await
    }

    async fn revoke_token(&self, token_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("tokens/{}", token_id);
        return self.delete(&uri, None, None).await
    }
}

// change to enums, ex application should be enum with application::applicationresponse and applicationparams

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ApplicationConfig {
    network_id: Option<String>,
    baselined: Option<bool>,
    webhook_secret: Option<String>,
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
    terms_of_service_agreed_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Token {
    id: String,
    expires_in: Option<i64>,
    token: Option<String>,
    permissions: Option<i32>,
    pub access_token: Option<String>,
    refresh_token: Option<String>,
    created_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthenticateResponse {
    pub user: User,
    pub token: Token,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Organization {
    id: String,
    created_at: String,
    name: String,
    user_id: String,
    description: String,
    metadata: serde_json::Value,
}



#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::name::en::{Name, FirstName, LastName};
    use fake::faker::internet::en::{FreeEmail, Password};
    use fake::{Fake};
    use serde_json::{json};

    const ROPSTEN_NETWORK_ID: &str = "66d44f30-9092-4182-a3c4-bc02736d6ae5";

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

    async fn generate_new_application(ident: &ApiClient, user_id: &str) -> Application {
        let application_data = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": user_id,
            "name": format!("{} {}", Name().fake::<String>(), "Application"),
            "description": "Some application description",
            "type": "baseline",
            "hidden": false
        }));

        let create_application_res = ident.create_application(application_data).await.expect("generate application response");
        assert_eq!(create_application_res.status(), 201);

        return create_application_res.json::<Application>().await.expect("create application body")
    }

    #[tokio::test]
    async fn create_user_and_authenticate() {
        let _ = generate_new_user_and_token().await;
    }

    #[tokio::test]
    async fn get_user() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let get_user_res = ident.get_user(authentication_res_body.user.id.as_str(), authentication_res_body.user.name.as_str(), None).await.expect("get user response");
        assert_eq!(get_user_res.status(), 200);
    }

    #[tokio::test]
    async fn list_users() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let get_users_res = ident.get_users().await.expect("get users response");
        assert_eq!(get_users_res.status(), 403)
    }

    #[tokio::test]
    async fn update_user() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let update_params = Some(json!({
            "name": Name().fake::<String>(),
        }));
        let update_user_res = ident.update_user(authentication_res_body.user.id.as_str(), authentication_res_body.user.name.as_str(), update_params).await.expect("update user response");
        assert_eq!(update_user_res.status(), 204);
    }

    #[tokio::test]
    async fn delete_user() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let delete_user_res = ident.delete_user(authentication_res_body.user.id.as_str()).await.expect("delete user response");
        assert_eq!(delete_user_res.status(), 403);
    }

    #[tokio::test]
    async fn create_organization() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_organization_params = Some(json!({
            "name": "ACME Inc.",
            "description": "Organization for testing",
            "user_id": authentication_res_body.user.id.as_str(),
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
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let list_organizations_res = ident.list_organizations().await.expect("list organizations response");
        assert_eq!(list_organizations_res.status(), 200);
    }

    #[tokio::test]
    async fn get_organization() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_organization_params = Some(json!({
            "name": "ACME Inc.",
            "description": "Organization for testing",
            "user_id": authentication_res_body.user.id.as_str(),
            "metadata": {
                "hello": "world",
                "arbitrary": "input"
            }
        }));
        let create_organization_res = ident.create_organization(create_organization_params).await.expect("create organization response");
        assert_eq!(create_organization_res.status(), 201);

        let create_organization_body = create_organization_res.json::<Organization>().await.expect("create organization body");

        let get_organization_res = ident.get_organization(create_organization_body.id.as_str()).await.expect("get organization response");
        assert_eq!(get_organization_res.status(), 200);
    }

    #[tokio::test]
    async fn update_organization() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_organization_params = Some(json!({
            "name": "ACME Inc.",
            "description": "Organization for testing",
            "user_id": authentication_res_body.user.id.as_str(),
            "metadata": {
                "hello": "world",
                "arbitrary": "input"
            }
        }));
        let create_organization_res = ident.create_organization(create_organization_params).await.expect("create organization response");
        assert_eq!(create_organization_res.status(), 201);
        
        let create_organization_body = create_organization_res.json::<Organization>().await.expect("create organization body");

        let update_organization_params = Some(json!({
            "name": "ACME Inc.",
            "description": "Updated description",
            "user_id": authentication_res_body.user.id.as_str(),
        }));
        let update_organization_res = ident.update_organization(create_organization_body.id.as_str(), update_organization_params).await.expect("update organization response");
        assert_eq!(update_organization_res.status(), 204);
    }

    #[tokio::test]
    async fn organization_authorization() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_organization_params = Some(json!({
            "name": "ACME Inc.",
            "description": "Organization for testing",
            "user_id": authentication_res_body.user.id.as_str(),
            "metadata": {
                "hello": "world",
                "arbitrary": "input"
            }
        }));
        let create_organization_res = ident.create_organization(create_organization_params).await.expect("create organization response");
        assert_eq!(create_organization_res.status(), 201);
        
        let create_organization_body = create_organization_res.json::<Organization>().await.expect("create organization body");

        let organization_authorization_params = Some(json!({
            "organization_id": create_organization_body.id,
            "scope": "offline_access"
        }));
        let organization_authorization_res = ident.organization_authorization(organization_authorization_params).await.expect("organization authorization response");
        assert_eq!(organization_authorization_res.status(), 201)
    }

    // FIXME
    #[tokio::test]
    async fn list_tokens() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_organization_params = Some(json!({
            "name": "ACME Inc.",
            "description": "Organization for testing",
            "user_id": authentication_res_body.user.id.as_str(),
            "metadata": {
                "hello": "world",
                "arbitrary": "input"
            }
        }));
        let create_organization_res = ident.create_organization(create_organization_params).await.expect("create organization response");
        assert_eq!(create_organization_res.status(), 201);
        
        let create_organization_body = create_organization_res.json::<Organization>().await.expect("create organization body");

        let organization_authorization_params = Some(json!({
            "organization_id": create_organization_body.id,
            "scope": "offline_access"
        }));
        let organization_authorization_res = ident.organization_authorization(organization_authorization_params).await.expect("organization authorization response");
        assert_eq!(organization_authorization_res.status(), 201);

        let organization_authorization_body = organization_authorization_res.json::<Token>().await.expect("organization authorization body");

        let list_tokens_params = Some(json!({
            "refresh_token": organization_authorization_body.refresh_token
        }));
        let list_tokens_res = ident.list_tokens(list_tokens_params).await.expect("list tokens res");
        assert_eq!(list_tokens_res.status(), 200);
    }

    #[tokio::test]
    async fn list_appications() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let list_applications_res = ident.list_applications().await.expect("list applications response");
        assert_eq!(list_applications_res.status(), 200);
    }

    #[tokio::test]
    async fn create_application() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let _ = generate_new_application(&ident, authentication_res_body.user.id.as_str()).await;
    }

    #[tokio::test]
    async fn get_application() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, authentication_res_body.user.id.as_str()).await;

        let get_application_res = ident.get_application(create_application_body.id.as_str()).await.expect("get application response");
        assert_eq!(get_application_res.status(), 200);
    }

    #[tokio::test]
    async fn update_application() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, authentication_res_body.user.id.as_str()).await;

        let update_application_params = Some(json!({
            "description": "An updated description"
        }));
        let update_application_res = ident.update_application(create_application_body.id.as_str(), update_application_params).await.expect("update application response");
        assert_eq!(update_application_res.status(), 204);
    }

    #[tokio::test]
    async fn delete_application() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, authentication_res_body.user.id.as_str()).await;

        let delete_application_res = ident.delete_application(create_application_body.id.as_str()).await.expect("delete application response");
        assert_eq!(delete_application_res.status(), 501);
    }

    #[tokio::test]
    async fn list_application_users() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, authentication_res_body.user.id.as_str()).await;

        let list_application_users_res = ident.list_application_users(create_application_body.id.as_str()).await.expect("list application users res");
        assert_eq!(list_application_users_res.status(), 200);
    }

    #[tokio::test]
    async fn associate_application_user() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let mut ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, authentication_res_body.user.id.as_str()).await;
        
        let application_authorization_params = Some(json!({
            "application_id": create_application_body.id,
            "scope": "offline_access"
        }));
        let application_authorization_res = ident.application_authorization(application_authorization_params).await.expect("application authorization response");
        assert_eq!(application_authorization_res.status(), 201);

        let application_authorization_body = application_authorization_res.json::<Token>().await.expect("organization authorization body");
        ident.token = match application_authorization_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let another_user_params = Some(json!({
            "first_name": FirstName().fake::<String>(),
            "last_name": LastName().fake::<String>(),
            "email": FreeEmail().fake::<String>(),
            "password": Password(std::ops::Range { start: 8, end: 15 }).fake::<String>(),
        }));
        let create_another_user_res = ident.create_user(another_user_params).await.expect("create another user response");
        assert_eq!(create_another_user_res.status(), 201);

        let another_user_body = create_another_user_res.json::<User>().await.expect("another user body");
        let associate_application_user_params = Some(json!({
            "user_id": another_user_body.id
        }));

        let associate_application_user_res = ident.associate_application_user(create_application_body.id.as_str(), associate_application_user_params).await.expect("associate application user response");
        assert_eq!(associate_application_user_res.status(), 204);
    }

    #[tokio::test]
    async fn application_authorization() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, authentication_res_body.user.id.as_str()).await;

        let application_authorization_params = Some(json!({
            "application_id": create_application_body.id,
            "scope": "offline_access"
        }));
        let application_authorization_res = ident.application_authorization(application_authorization_params).await.expect("application authorization response");
        assert_eq!(application_authorization_res.status(), 201);
    }

    #[tokio::test]
    async fn revoke_token() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, authentication_res_body.user.id.as_str()).await;

        let application_authorization_params = Some(json!({
            "application_id": create_application_body.id
        }));
        let application_authorization_res = ident.application_authorization(application_authorization_params).await.expect("application authorization response");
        assert_eq!(application_authorization_res.status(), 201);

        let application_authorization_body = application_authorization_res.json::<Token>().await.expect("application authorization body");

        let revoke_token_res = ident.revoke_token(application_authorization_body.id.as_str()).await.expect("revoke token response");
        assert_eq!(revoke_token_res.status(), 204);
    }
}

// users
//  create user - done
//  list users - done
//  get user detail - done (403)
//  update user - done
//  delete user - done (403)

// organizations
//  create organization - done
//  list organizations - done
//  get organization details - done
//  update organization details - done

// applications
//  create application - done
//  list applications - done
//  get application details - done
//  update application - done
//  delete application - done (501)
//  list application users - done
//  associate application user - done

// authentication / authorization
//  user authentication - done
//  list revocable tokens - done
//  application authorization - done
//  organization authorization - done
//  revoke token - done

// TODO
// seperate application / organization authorization calls are unnecessary
// seperate token struct for ^ response
// rename Token struct or combine all token structs into 1 (enum?)
// seperate generate user and token into 2 helper functions
// create generate organization helper
// the token properties shouldn't be public?
// token enum - beaertoken, accessandresponsetoken, machinetomachine, revokabletoken
// new fn? (as contructor)
// check my pattern w passing references / values through functions
// basically all of these "optional" params (body) are not really optional - change them to required?
// should add required data struct in fn call args, referencing ^