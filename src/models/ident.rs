// change to enums, ex application should be enum with application::applicationresponse and applicationparams
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ApplicationConfig {
    network_id: Option<String>,
    baselined: Option<bool>,
    webhook_secret: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Application {
    pub id: String,
    created_at: String,
    network_id: String,
    user_id: String,
    pub name: String,
    description: Option<String>,
    r#type: Option<String>,
    config: ApplicationConfig,
    hidden: bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct User {
    pub id: String,
    created_at: String,
    pub name: String,
    first_name: String,
    last_name: String,
    pub email: String,
    permissions: i32,
    privacy_policy_agreed_at: Option<String>,
    terms_of_service_agreed_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Token {
    pub id: String,
    expires_in: Option<i64>,
    pub token: Option<String>,
    permissions: Option<i32>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    created_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthenticateResponse {
    pub user: User,
    pub token: Token,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Organization {
    pub id: String,
    created_at: String,
    pub name: String,
    user_id: String,
    description: String,
    pub metadata: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Invite {
    application_id: Option<String>,
    user_id: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    invitor_id: Option<String>,
    invitor_name: Option<String>,
    organization_id: Option<String>,
    organization_name: Option<String>,
    permissions: Option<i32>,
    params: Option<Value>,
}
