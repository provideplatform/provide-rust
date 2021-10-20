pub use crate::client::{ApiClient, AdditionalHeader};
use std::result::{Result};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use serde_json::{Value};

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "baseline.provide.network";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait Baseline {
    fn factory(token: String) -> Self;

    async fn get_bpi_accounts(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_bpi_account(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_bpi_account(&self, account_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_message(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_subjects(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_subject(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_subject(&self, subject_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn update_subject(&self, subject_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_subject_account(&self, subject_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_subject_account(&self, subject_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_subject_subject_account(&self, subject_id: &str, account_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_workflows(&self) -> Result<reqwest::Response, reqwest::Error>;
        
    async fn create_workflow(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_workflow(&self, workflow_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_workflow_worksteps(&self, workflow_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_workflow_workstep(&self, workflow_id: &str, workstep_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_workgroups(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_workgroup(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;
    
    async fn get_workgroup(&self, workgroup_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn update_workgroup(&self, workgroup_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_workgroup_subjects(&self, workgroup_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn associate_workgroup_subject(&self, workgroup_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_object(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn update_object(&self, object_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_state(&self, state_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_state_objects(&self) -> Result<reqwest::Response, reqwest::Error>;
}

#[async_trait]
impl Baseline for ApiClient {
    fn factory(token: String) -> Self {
        let scheme = std::env::var("BASELINE_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("BASELINE_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("BASELINE_API_PATH").unwrap_or(String::from(DEFAULT_PATH));
    
        return ApiClient::new(scheme, host, path, token);
    }

    async fn get_bpi_accounts(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("bpi_accounts", None, None).await
    }

    async fn create_bpi_account(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("bpi_accounts", params, None).await
    }

    async fn get_bpi_account(&self, account_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("bpi_accounts/{}", account_id);
        return self.get(&uri, None, None).await
    }

    async fn create_message(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("protocol_messages", params, None).await
    }

    async fn get_subjects(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("subjects", None, None).await
    }

    async fn create_subject(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("subjects", params, None).await
    }

    async fn get_subject(&self, subject_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("subjects/{}", subject_id);
        return self.get(&uri, None, None).await
    }

    async fn update_subject(&self, subject_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("subjects/{}", subject_id);
        return self.put(&uri, params, None).await
    }

    async fn get_subject_account(&self, subject_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.get(&uri, None, None).await
    }

    async fn create_subject_account(&self, subject_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.post(&uri, params, None).await
    }

    async fn get_subject_subject_account(&self, subject_id: &str, account_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("subjects/{}/accounts/{}", subject_id, account_id);
        return self.get(&uri, None, None).await
    }

    async fn get_workflows(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("workflows", None, None).await
    }

    async fn create_workflow(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("workflows", params, None).await
    }

    async fn get_workflow(&self, workflow_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("workflows/{}", workflow_id);
        return self.get(&uri, None, None).await
    }

    async fn get_workflow_worksteps(&self, workflow_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("workflows/{}/worksteps", workflow_id);
        return self.get(&uri, None, None).await
    }

    async fn get_workflow_workstep(&self, workflow_id: &str, workstep_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.get(&uri, None, None).await
    }

    async fn get_workgroups(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("workgroups", None, None).await
    }

    async fn create_workgroup(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("workgroups", params, None).await
    }

    async fn get_workgroup(&self, workgroup_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("workgroups/{}", workgroup_id);
        return self.get(&uri, None, None).await
    }

    async fn update_workgroup(&self, workgroup_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("workgroups/{}", workgroup_id);
        return self.put(&uri, params, None).await
    }

    async fn get_workgroup_subjects(&self, workgroup_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("workgroups/{}/subjects", workgroup_id);
        return self.get(&uri, None, None).await
    }

    // change params to subject id
    async fn associate_workgroup_subject(&self, workgroup_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("workgroups/{}/subjects", workgroup_id);
        return self.post(&uri, params, None).await
    }

    async fn create_object(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("objects", params, None).await
    }

    async fn update_object(&self, object_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("objects/{}", object_id);
        return self.put(&uri, params, None).await
    }

    async fn get_state(&self, state_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("states/{}", state_id);
        return self.get(&uri, None, None).await
    }

    async fn get_state_objects(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("states", None, None).await
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct BpiAccount {
    context: Value, // FIXME: apparently this is @context
    balances: Value,
    created_at: String,
    owners: Value,
    id: String,
    metadata: Value,
    nonce: i64,
    security_policies: Value,
    state_claims: Value,
    workflows: Value,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Subject {
    created_at: String,
    description: String, // this is probably optional
    id: String,
    metadata: Value,
    name: String,
    r#type: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::name::en::{Name, FirstName, LastName};
    use fake::faker::internet::en::{FreeEmail, Password};
    use fake::{Fake};
    use crate::ident::{Ident, AuthenticateResponse, Application, Token};
    use serde_json::json;

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

    #[tokio::test]
    async fn get_bpi_accounts() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let baseline: ApiClient = Baseline::factory(access_token);
        println!("{:?}", baseline.base_url);

        let get_bpi_acconts_res = baseline.get_bpi_accounts().await.expect("get bpi accounts response");
        assert_eq!(get_bpi_acconts_res.status(), 200);
    }

    #[tokio::test]
    async fn create_bpi_account() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let baseline: ApiClient = Baseline::factory(access_token);

        let create_bpi_account_params = Some(json!({
            "owners": [
                "did:prvd:7cb23e2b-07ed-4562-8afb-73955f8f17c5" // FIXME: make this faker
              ],
              "security_policies": [
                {
                  "type": "AuthenticationPolicy",
                  "reference": "https://example.com/policies/authentication-policy.json"
                }
              ],
              "nonce": 4114,
              "workflows": {
                "$ref": "#/components/schemas/WorkflowInstance"
              }
        }));

        let create_bpi_accont_res = baseline.create_bpi_account(create_bpi_account_params).await.expect("create bpi account response");
        assert_eq!(create_bpi_accont_res.status(), 201);
    }

    #[tokio::test]
    async fn get_bpi_account() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let baseline: ApiClient = Baseline::factory(access_token);

        let create_bpi_account_params = Some(json!({
            "owners": [
                "did:prvd:7cb23e2b-07ed-4562-8afb-73955f8f17c5" // FIXME: make this faker
              ],
              "security_policies": [
                {
                  "type": "AuthenticationPolicy",
                  "reference": "https://example.com/policies/authentication-policy.json"
                }
              ],
              "nonce": 4114,
              "workflows": {
                "$ref": "#/components/schemas/WorkflowInstance"
              }
        }));

        let create_bpi_accont_res = baseline.create_bpi_account(create_bpi_account_params).await.expect("create bpi account response");
        assert_eq!(create_bpi_accont_res.status(), 201);

        let create_bpi_account_body = create_bpi_accont_res.json::<BpiAccount>().await.expect("create bpi account body");

        let get_bpi_account_res = baseline.get_bpi_account(&create_bpi_account_body.id).await.expect("get bpi account response");
        assert_eq!(get_bpi_account_res.status(), 200);
    }

    #[tokio::test]
    async fn create_message() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let baseline: ApiClient = Baseline::factory(access_token);

        // FIXME: need to generate proof here, make generate proof helper
        let create_message_params = Some(json!({
            "proof": "string",
            "type": "string",
            "witness": {}
        }));

        let create_message_res = baseline.create_message(create_message_params).await.expect("create message response");
        assert_eq!(create_message_res.status(), 201);
    }

    #[tokio::test]
    async fn get_subjects() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let baseline: ApiClient = Baseline::factory(access_token);

        let get_subjects_res = baseline.get_subjects().await.expect("get subjects response");
        assert_eq!(get_subjects_res.status(), 200);
    }

    #[tokio::test]
    async fn create_subject() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let baseline: ApiClient = Baseline::factory(access_token);

        // FIXME: need to make generate wallet helper
        let create_subject_params = Some(json!({
            "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
            "credentials": [],
            "description": "Organization for testing",
            "metadata": {},
            "name": "ACME Inc.",
            "type": "Organization"
        }));

        let create_subject_res = baseline.create_subject(create_subject_params).await.expect("create subject response");
        assert_eq!(create_subject_res.status(), 201);
    }

    #[tokio::test]
    async fn get_subject() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let baseline: ApiClient = Baseline::factory(access_token);

        // FIXME: need to make generate wallet helper
        let create_subject_params = Some(json!({
            "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
            "credentials": [],
            "description": "Organization for testing",
            "metadata": {},
            "name": "ACME Inc.",
            "type": "Organization"
        }));

        let create_subject_res = baseline.create_subject(create_subject_params).await.expect("create subject response");
        assert_eq!(create_subject_res.status(), 201);

        let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

        let get_subject_res = baseline.get_subject(&create_subject_body.id).await.expect("get subject response");
        assert_eq!(get_subject_res.status(), 200);
    }

    #[tokio::test]
    async fn update_subject() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let baseline: ApiClient = Baseline::factory(access_token);

        // FIXME: need to make generate wallet helper
        let create_subject_params = Some(json!({
            "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
            "credentials": [],
            "description": "Organization for testing",
            "metadata": {},
            "name": "ACME Inc.",
            "type": "Organization"
        }));

        let create_subject_res = baseline.create_subject(create_subject_params).await.expect("create subject response");
        assert_eq!(create_subject_res.status(), 201);

        let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

        let update_subject_params = Some(json!({
            "description": "Some updated description",
        }));

        let update_subject_res = baseline.update_subject(&create_subject_body.id, update_subject_params).await.expect("update subject response");
        assert_eq!(update_subject_res.status(), 204);
    }

    #[tokio::test]
    async fn get_subject_account() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let baseline: ApiClient = Baseline::factory(access_token);

        // FIXME: need to make generate wallet helper
        let create_subject_params = Some(json!({
            "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
            "credentials": [],
            "description": "Organization for testing",
            "metadata": {},
            "name": "ACME Inc.",
            "type": "Organization"
        }));

        let create_subject_res = baseline.create_subject(create_subject_params).await.expect("create subject response");
        assert_eq!(create_subject_res.status(), 201);

        let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

        let get_subject_account_res = baseline.get_subject_account(&create_subject_body.id).await.expect("get subject account response");
        assert_eq!(get_subject_account_res.status(), 200);
    }
}