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

    async fn get_subject_accounts(&self, subject_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_subject_account(&self, subject_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_subject_account(&self, subject_id: &str, account_id: &str) -> Result<reqwest::Response, reqwest::Error>;

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

    async fn get_subject_accounts(&self, subject_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.get(&uri, None, None).await
    }

    async fn create_subject_account(&self, subject_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.post(&uri, params, None).await
    }

    async fn get_subject_account(&self, subject_id: &str, account_id: &str) -> Result<reqwest::Response, reqwest::Error> {
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

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SubjectAccount {
    context: Value, // FIXME: apparently this is @context
    id: String,
    bpi_account_ids: Vec<String>,
    created_at: String,
    credentials: Value,
    metadata: Value,
    r#type: String,
    recovery_policy: Value,
    role: Value,
    subject_id: String,
    security_policies: Value,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Workflow {
    id: String,
    name: String,
    r#type: String,
    workstep_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Workgroup {
    subject_id: String,
    config: Value,
    created_at: String,
    description: String,
    id: String,
    name: String,
    network_id: String,
    r#type: String,
    security_policies: Value,
    admins: Vec<String>,
}


#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::name::en::{Name, FirstName, LastName};
    use fake::faker::internet::en::{FreeEmail, Password};
    use fake::{Fake};
    use crate::ident::{Ident, AuthenticateResponse, Application, Token, Organization};
    use crate::nchain::{NChain, Account, Contract};
    use crate::vault::{Vault, VaultContainer};
    use serde_json::json;
    use tokio::time::{self, Duration};
    use std::process::Command;

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

    async fn generate_application(ident: &ApiClient, user_id: &str) -> Application {
        let application_data = json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": user_id,
            "name": format!("{} {}", Name().fake::<String>(), "Application"),
            "description": "Some application description",
            "type": "baseline",
            "hidden": false
        });

        let create_application_res = ident.create_application(Some(application_data)).await.expect("generate application response");
        assert_eq!(create_application_res.status(), 201);

        return create_application_res.json::<Application>().await.expect("create application body")
    }

    async fn generate_organization(ident: &ApiClient, user_id: &str) -> Organization {
        let create_organization_params = Some(json!({
            "name": format!("{} organization", Name().fake::<String>()),
            "description": "Organization for testing",
            "user_id": user_id,
            "metadata": {
                "hello": "world",
                "arbitrary": "input"
            },
        }));
        let create_organization_res = ident.create_organization(create_organization_params).await.expect("create organization response");
        assert_eq!(create_organization_res.status(), 201);

        return create_organization_res.json::<Organization>().await.expect("generate organization body")
    }

    async fn generate_subject(baseline: &ApiClient) -> Subject {
        // FIXME: need to make generate wallet helper
        let create_subject_params = Some(json!({
            "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
            "credentials": [],
            "description": "Organization for testing",
            "metadata": {},
            "name": format!("{} subject", Name().fake::<String>()),
            "type": "Organization"
        }));

        let create_subject_res = baseline.create_subject(create_subject_params).await.expect("create subject response");
        assert_eq!(create_subject_res.status(), 201);

        return create_subject_res.json::<Subject>().await.expect("generate subject response");
    }

    #[tokio::test]
    async fn setup() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        // create organization
        let create_organization_body = generate_organization(&ident, &authentication_res_body.user.id).await;
        let organization_authorization_params = json!({
            "organization_id": &create_organization_body.id,
            "scope": "offline_access",
        });
        let organization_authorization_res = ident.organization_authorization(Some(organization_authorization_params)).await.expect("organization authorization response");
        let organization_auth_body = organization_authorization_res.json::<Token>().await.expect("organization authorization body");
        let org_refresh_token = match organization_auth_body.refresh_token {
            Some(string) => string,
            None => panic!("organization authorization refresh token not found"),
        };

        // create application
        let create_application_body = generate_application(&ident, &authentication_res_body.user.id).await;
        let application_authorization_params = json!({
            "application_id": create_application_body.id,
            "scope": "offline_access"
        });
        let application_authorization_res = ident.application_authorization(Some(application_authorization_params)).await.expect("application authorization response");
        let application_auth_body = application_authorization_res.json::<Token>().await.expect("application authorization body");
        let app_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authorization access token not found"),
        };
        let app_refresh_token = match application_auth_body.refresh_token {
            Some(string) => string,
            None => panic!("application authorization refresh token not found"),
        };

        // registry contract
        // get shuttle contract
        let registry_contracts_res = ident.client.get("https://s3.amazonaws.com/static.provide.services/capabilities/provide-capabilities-manifest.json").send().await.expect("get registry contracts response");
        let registry_contracts = registry_contracts_res.json::<Value>().await.expect("registry contracts body");
        let shuttle_contract = &registry_contracts["baseline"]["contracts"][2];
        
        let nchain: ApiClient = NChain::factory(app_access_token.clone());
        
        // deploy workgroup contract
        let create_account_params = json!({
            "network_id": ROPSTEN_NETWORK_ID,
        });
        let create_account_res = nchain.create_account(Some(create_account_params)).await.expect("create account response");
        let create_account_body = create_account_res.json::<Account>().await.expect("create account body");
        let create_contract_params = json!({
            "address": "0x",
            "params": {
                "account_id": &create_account_body.id,
                "compiled_artifact": shuttle_contract,
                "argv": [],
            },
            "name": "Shuttle",
            "network_id": ROPSTEN_NETWORK_ID,
            "type": "registry",
        });
        let create_contract_res = nchain.create_contract(Some(create_contract_params)).await.expect("create contract response");
        let create_contract_body = create_contract_res.json::<Contract>().await.expect("create contract body");
       
        // require workgroup contract ("organization-registry")
        // wait until address of new contract isn't 0x
        let mut interval = time::interval(Duration::from_millis(500));
        let mut registry_contract_address = create_contract_body.address;

        while registry_contract_address == "0x" {
            interval.tick().await;

            let get_contract_res = nchain.get_contract(&create_contract_body.id).await.expect("get contract response");
            assert_eq!(get_contract_res.status(), 200);

            let get_contract_body = get_contract_res.json::<Contract>().await.expect("get contract body");
            registry_contract_address = get_contract_body.address;
        }

        println!("registry contract address {:?}", registry_contract_address);

        let vault: ApiClient = Vault::factory(app_access_token.clone());

        let get_vaults_res = vault.list_vaults().await.expect("list vaults response");
        let mut get_vaults_body = get_vaults_res.json::<Vec<VaultContainer>>().await.expect("get vaults body");

        let mut count = 0;

        while count != 5 {
            interval.tick().await;
            count += 1;

            let vaults_res = vault.list_vaults().await.expect("list vaults response");
            get_vaults_body = vaults_res.json::<Vec<VaultContainer>>().await.expect("get vaults body");
        }

        println!("vaults: {:?}", get_vaults_body);
        println!("count: {}", count);
        // resolve organization address
        // get keys
        //  initialize vault client
        //  requireVault
        //      fetch vaults then return [0]
        //      get keys of that vault
        //          return address of last secp256k1



        assert_eq!(201, 200);
        // create workgroup contract
        // require workgroup contract
        // resolve workgroup contract
        // get contract that is workgroup scoped
        
        // let get_contracts_res = nchain.get_contracts().await.expect("get contracts response");

        // config file
        // let config_file_contents = format!("access-token: {}\nrefresh-token: {}\n{}:\n  api-token: {}\n");
        // let config_file_name = format!();

        // organization address
        // get org token
        // require vault
        // get last address from last secp256k1
        
        // registery contract address

        // let run_env = format!("LOG_LEVEL=TRACE IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http NCHAIN_API_HOST=localhost:8084 NCHAIN_API_SCHEME=http VAULT_API_HOST=localhost:8082 VAULT_API_SCHEME=http PROVIDE_ORGANIZATION_REFRESH_TOKEN={}", org_refresh_token);

        // let mut run_cmd = String::from("prvd baseline stack start");
        // run_cmd += format!("--api-endpoint=\"{}\"", "http://localhost:8085");
        // run_cmd += "--config="; <-------------------------
        // run_cmd += format!("--ident-host=\"{}\"", "localhost:8081");
        // run_cmd += format!("--ident-scheme=\"{}\"", "http");
        // run_cmd += format!("--messaging-endpoint=\"{}\"", "nats://localhost:4222");
        // run_cmd += format!("--name=\"{}\"", &create_organization_body.name);
        // run_cmd += format!("--nats-auth-token=\"{}\"", "testtoken");
        // run_cmd += format!("--nats-port=\"{}\"", "4222");
        // run_cmd += format!("--nchain-host=\"{}\"", "localhost:8084");
        // run_cmd += format!("--nchain-scheme=\"{}\"", "http");
        // run_cmd += format!("--nchain-network-id=\"{}\"", ROPSTEN_NETWORK_ID);
        // run_cmd += format!("--organization=\"{}\"", &create_organization_body.id);
        // run_cmd += format!("--organization-address=\"{}\"", ""); <-------------------------
        // run_cmd += format!("--organization-refresh-token=\"{}\"", &org_refresh_token);
        // run_cmd += format!("--port=\"{}\"", "8085");
        // run_cmd += format!("--privacy-host=\"{}\"", "localhost:8083");
		// run_cmd += format!("--privacy-scheme=\"{}\"", "http");
		// run_cmd += format!("--registry-contract-address=\'{}\"", &registry_contract_address);
        // run_cmd += format!("--redis-hostname=\"{}\"", "redis");
        // run_cmd += format!("--redis-port=\"{}\"", "6379");
        // run_cmd += format!("--sor=\"{}\"", "ephemeral");
        // run_cmd += format!("--vault-host=\"{}\"", "localhost:8080");
		// run_cmd += format!("--vault-refresh-token=\"{}\"", &org_refresh_token);
		// run_cmd += format!("--vault-scheme=\"{}\"", "http");
		// run_cmd += format!("--workgroup=\"{}\"", &create_application_body.name);

        // let baseline_cmd = format!("{} {}", run_env, run_cmd);

        // Command::new(baseline_cmd).spawn().expect("baseline tests init process");
        // create application
        // create app token w offline access scope

    }

    // #[tokio::test]
    // async fn get_bpi_accounts() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let get_bpi_acconts_res = baseline.get_bpi_accounts().await.expect("get bpi accounts response");
    //     assert_eq!(get_bpi_acconts_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_bpi_account() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let ident: ApiClient = Ident::factory(access_token.clone());
    //     let create_organization_body = generate_organization(&ident, &authentication_res_body.user.id).await;

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_bpi_account_params = Some(json!({
    //         "owners": [
    //             format!("did:prvd:{}", &create_organization_body.id)
    //           ],
    //           "security_policies": [
    //             {
    //               "type": "AuthenticationPolicy",
    //               "reference": "https://example.com/policies/authentication-policy.json"
    //             }
    //           ],
    //           "nonce": 4114,
    //           "workflows": {},
    //     }));

    //     let create_bpi_accont_res = baseline.create_bpi_account(create_bpi_account_params).await.expect("create bpi account response");
    //     assert_eq!(create_bpi_accont_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn get_bpi_account() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let ident: ApiClient = Ident::factory(access_token.clone());
    //     let create_organization_body = generate_organization(&ident, &authentication_res_body.user.id).await;

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_bpi_account_params = Some(json!({
    //         "owners": [
    //             format!("did:prvd:{}", &create_organization_body.id)
    //           ],
    //           "security_policies": [
    //             {
    //               "type": "AuthenticationPolicy",
    //               "reference": "https://example.com/policies/authentication-policy.json"
    //             }
    //           ],
    //           "nonce": 4114,
    //           "workflows": {},
    //     }));

    //     let create_bpi_accont_res = baseline.create_bpi_account(create_bpi_account_params).await.expect("create bpi account response");

    //     let create_bpi_account_body = create_bpi_accont_res.json::<BpiAccount>().await.expect("create bpi account body");

    //     let get_bpi_account_res = baseline.get_bpi_account(&create_bpi_account_body.id).await.expect("get bpi account response");
    //     assert_eq!(get_bpi_account_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_message() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     // FIXME: need to generate proof here, make generate proof helper
    //     let create_message_params = Some(json!({
    //         "proof": "string",
    //         "type": "string",
    //         "witness": {}
    //     }));

    //     let create_message_res = baseline.create_message(create_message_params).await.expect("create message response");
    //     assert_eq!(create_message_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn get_subjects() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let get_subjects_res = baseline.get_subjects().await.expect("get subjects response");
    //     assert_eq!(get_subjects_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_subject() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

        // // FIXME: need to make generate wallet helper
        // let create_subject_params = Some(json!({
        //     "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
        //     "credentials": [],
        //     "description": "Organization for testing",
        //     "metadata": {},
        //     "name": format!("{} subject", Name().fake::<String>()),
        //     "type": "Organization"
        // }));

        // let create_subject_res = baseline.create_subject(create_subject_params).await.expect("create subject response");
        // assert_eq!(create_subject_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn get_subject() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     // FIXME: need to make generate wallet helper
    //     let create_subject_params = Some(json!({
    //         "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
    //         "credentials": [],
    //         "description": "Organization for testing",
    //         "metadata": {},
    //         "name": "ACME Inc.",
    //         "type": "Organization"
    //     }));

    //     let create_subject_res = baseline.create_subject(create_subject_params).await.expect("create subject response");
    //     assert_eq!(create_subject_res.status(), 201);

    //     let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

    //     let get_subject_res = baseline.get_subject(&create_subject_body.id).await.expect("get subject response");
    //     assert_eq!(get_subject_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn update_subject() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     // FIXME: need to make generate wallet helper
    //     let create_subject_params = Some(json!({
    //         "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
    //         "credentials": [],
    //         "description": "Organization for testing",
    //         "metadata": {},
    //         "name": "ACME Inc.",
    //         "type": "Organization"
    //     }));

    //     let create_subject_res = baseline.create_subject(create_subject_params).await.expect("create subject response");
    //     assert_eq!(create_subject_res.status(), 201);

    //     let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

    //     let update_subject_params = Some(json!({
    //         "description": "Some updated description",
    //     }));

    //     let update_subject_res = baseline.update_subject(&create_subject_body.id, update_subject_params).await.expect("update subject response");
    //     assert_eq!(update_subject_res.status(), 204);

    //     // how to create workstep from api
    // }

    // #[tokio::test]
    // async fn get_subject_accounts() {
        // let authentication_res_body = generate_new_user_and_token().await;
        // let access_token = match authentication_res_body.token.access_token {
        //     Some(string) => string,
        //     None => panic!("authentication response access token not found"),
        // };

        // let baseline: ApiClient = Baseline::factory(access_token);

    //     // FIXME: need to make generate wallet helper
    //     let create_subject_params = Some(json!({
    //         "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
    //         "credentials": [],
    //         "description": "Organization for testing",
    //         "metadata": {},
    //         "name": "ACME Inc.",
    //         "type": "Organization"
    //     }));

    //     let create_subject_res = baseline.create_subject(create_subject_params).await.expect("create subject response");
    //     assert_eq!(create_subject_res.status(), 201);

    //     let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

    //     let get_subject_account_res = baseline.get_subject_accounts(&create_subject_body.id).await.expect("get subject account response");
    //     assert_eq!(get_subject_account_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_subject_account() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_subject_body = generate_subject(&baseline).await;

    //     let create_subject_account_params = Some(json!({
    //         "@context": [],
    //         "bpi_account_ids": [ // FIXME
    //             "6bb23e2b-07ed-4562-8afb-73955f8f17c5",
    //             "7cb11a1a-01ca-3421-6fbd-42651c1a32a1"
    //         ],
    //         "credentials": {
    //             "credential_type": "JWS",
    //             "credentials": {
    //             "id": "https://example.com/issuer/123#ovsDKYBjFemIy8DVhc-w2LSi8CvXMw2AYDzHj04yxkc",
    //             "type": "JsonWebKey2020",
    //             "controller": "https://example.com/issuer/123",
    //             "publicKeyJwk": {
    //                 "kty": "OKP",
    //                 "crv": "Ed25519",
    //                 "x": "CV-aGlld3nVdgnhoZK0D36Wk-9aIMlZjZOK2XhPMnkQ"
    //             }
    //             }
    //         },
    //         "metadata": {},
    //         "type": "ProvideSubjectAccount",
    //         "recovery_policy": {
    //             "type": "recoveryKeyPolicy",
    //             "reference": ""
    //         },
    //         "role": {
    //             "name": "Organization",
    //             "reference": "https://example.com/roles/organization.json"
    //         },
    //         "subject_id": format!("did:prvd:{}", &create_subject_body.id), // FIXME
    //         "security_policies": {
    //             "type": "AuthenticationPolicy",
    //             "reference": ""
    //         }
    //     }));

    //     let create_subject_account_res = baseline.create_subject_account(&create_subject_body.id, create_subject_account_params).await.expect("create subject account response");
    //     assert_eq!(create_subject_account_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn get_subject_account() {
        // let authentication_res_body = generate_new_user_and_token().await;
        // let access_token = match authentication_res_body.token.access_token {
        //     Some(string) => string,
        //     None => panic!("authentication response access token not found"),
        // };

        // let baseline: ApiClient = Baseline::factory(access_token);

        // let create_subject_body = generate_subject(&baseline).await;

    //     let create_subject_account_params = Some(json!({
    //         "@context": [],
    //         "bpi_account_ids": [ // FIXME
    //             "6bb23e2b-07ed-4562-8afb-73955f8f17c5",
    //             "7cb11a1a-01ca-3421-6fbd-42651c1a32a1"
    //         ],
    //         "credentials": {
    //             "credential_type": "JWS",
    //             "credentials": {
    //             "id": "https://example.com/issuer/123#ovsDKYBjFemIy8DVhc-w2LSi8CvXMw2AYDzHj04yxkc",
    //             "type": "JsonWebKey2020",
    //             "controller": "https://example.com/issuer/123",
    //             "publicKeyJwk": {
    //                 "kty": "OKP",
    //                 "crv": "Ed25519",
    //                 "x": "CV-aGlld3nVdgnhoZK0D36Wk-9aIMlZjZOK2XhPMnkQ"
    //             }
    //             }
    //         },
    //         "metadata": {},
    //         "type": "ProvideSubjectAccount",
    //         "recovery_policy": {
    //             "type": "recoveryKeyPolicy",
    //             "reference": ""
    //         },
    //         "role": {
    //             "name": "Organization",
    //             "reference": "https://example.com/roles/organization.json"
    //         },
    //         "subject_id": format!("did:prvd:{}", &create_subject_body.id), // FIXME
    //         "security_policies": {
    //             "type": "AuthenticationPolicy",
    //             "reference": ""
    //         }
    //     }));

    //     let create_subject_account_res = baseline.create_subject_account(&create_subject_body.id, create_subject_account_params).await.expect("create subject account response");
        
    //     let create_subject_account_body = create_subject_account_res.json::<SubjectAccount>().await.expect("create subject account body");

    //     let get_subject_account_res = baseline.get_subject_account(&create_subject_body.id, &create_subject_account_body.id).await.expect("get subject account response");
    //     assert_eq!(get_subject_account_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn get_workflows() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let get_workflows_res = baseline.get_workflows().await.expect("get workflows response");
    //     assert_eq!(get_workflows_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_workflow() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_workflow_params = Some(json!({
    //         "name": "Procure to Pay",
    //         "type": "procure_to_pay",
    //     }));

    //     let create_workflow_res = baseline.create_workflow(create_workflow_params).await.expect("create workflow response");
    //     assert_eq!(create_workflow_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn get_workflow() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_workflow_params = Some(json!({
    //         "name": "Procure to Pay",
    //         "type": "procure_to_pay",
    //     }));

    //     let create_workflow_res = baseline.create_workflow(create_workflow_params).await.expect("create workflow response");

    //     let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

    //     let get_workflow_res = baseline.get_workflow(&create_workflow_body.id).await.expect("get workflow response");
    //     assert_eq!(get_workflow_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn get_workflow_worksteps() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_workflow_params = Some(json!({
    //         "name": "Procure to Pay",
    //         "type": "procure_to_pay",
    //     }));

    //     let create_workflow_res = baseline.create_workflow(create_workflow_params).await.expect("create workflow response");

    //     let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

    //     let get_workflow_worksteps_res = baseline.get_workflow_worksteps(&create_workflow_body.id).await.expect("get workflow worksteps response");
    //     assert_eq!(get_workflow_worksteps_res.status(), 200);
    // }

    // // how to create workflow workstep

    // // #[tokio::test]
    // // async fn get_workflow_workstep() {}

    // #[tokio::test]
    // async fn get_workgroups() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let get_workgroups_res = baseline.get_workgroups().await.expect("get workgroups response");
    //     assert_eq!(get_workgroups_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_workgroup() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_subject_body = generate_subject(&baseline).await;

    //     let create_workgroup_params = Some(json!({
    //         "subject_id": format!("did:prvd:{}", &create_subject_body.id),
    //         "description": "An example of the request body for workgroup creation",
    //         "name": "Example workgroup",
    //         "network_id": "07102258-5e49-480e-86af-6d0c3260827d",
    //         "type": "baseline",
    //         "security_policies": [],
    //         "admins": [
    //             format!("did:prvd:{}", &create_subject_body.id),
    //         ],
    //     }));

    //     let create_workgroup_res = baseline.create_workgroup(create_workgroup_params).await.expect("create workgroup response");
    //     assert_eq!(create_workgroup_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn get_workgroup() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_subject_body = generate_subject(&baseline).await;

    //     let create_workgroup_params = Some(json!({
    //         "subject_id": format!("did:prvd:{}", &create_subject_body.id),
    //         "description": "An example of the request body for workgroup creation",
    //         "name": "Example workgroup",
    //         "network_id": "07102258-5e49-480e-86af-6d0c3260827d",
    //         "type": "baseline",
    //         "security_policies": [],
    //         "admins": [
    //             format!("did:prvd:{}", &create_subject_body.id),
    //         ],
    //     }));

    //     let create_workgroup_res = baseline.create_workgroup(create_workgroup_params).await.expect("create workgroup response");

    //     let create_workgroup_body = create_workgroup_res.json::<Workgroup>().await.expect("create workgroup body");

    //     let get_workgroup_res = baseline.get_workgroup(&create_workgroup_body.id).await.expect("get workgroup response");
    //     assert_eq!(get_workgroup_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn update_workgroup() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_subject_body = generate_subject(&baseline).await;

    //     let create_workgroup_params = Some(json!({
    //         "subject_id": format!("did:prvd:{}", &create_subject_body.id),
    //         "description": "An example of the request body for workgroup creation",
    //         "name": "Example workgroup",
    //         "network_id": "07102258-5e49-480e-86af-6d0c3260827d",
    //         "type": "baseline",
    //         "security_policies": [],
    //         "admins": [
    //             format!("did:prvd:{}", &create_subject_body.id),
    //         ],
    //     }));

    //     let create_workgroup_res = baseline.create_workgroup(create_workgroup_params).await.expect("create workgroup response");

    //     let create_workgroup_body = create_workgroup_res.json::<Workgroup>().await.expect("create workgroup body");

    //     let update_workgroup_params = Some(json!({
    //         "description": "Some udpated workgroup description",
    //     }));

    //     let update_workgroup_res = baseline.update_workgroup(&create_workgroup_body.id, update_workgroup_params).await.expect("update workgroup response");
    //     assert_eq!(update_workgroup_res.status(), 204);
    // }

    // #[tokio::test]
    // async fn get_workgroup_subjects() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_subject_body = generate_subject(&baseline).await;

    //     let create_workgroup_params = Some(json!({
    //         "subject_id": format!("did:prvd:{}", &create_subject_body.id),
    //         "description": "An example of the request body for workgroup creation",
    //         "name": "Example workgroup",
    //         "network_id": "07102258-5e49-480e-86af-6d0c3260827d",
    //         "type": "baseline",
    //         "security_policies": [],
    //         "admins": [
    //             format!("did:prvd:{}", &create_subject_body.id),
    //         ],
    //     }));

    //     let create_workgroup_res = baseline.create_workgroup(create_workgroup_params).await.expect("create workgroup response");

    //     let create_workgroup_body = create_workgroup_res.json::<Workgroup>().await.expect("create workgroup body");

    //     let get_workgroup_subjects_res = baseline.get_workgroup_subjects(&create_workgroup_body.id).await.expect("get workgroup subjects response");
    //     assert_eq!(get_workgroup_subjects_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn associate_workgroup_subject() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let baseline: ApiClient = Baseline::factory(access_token);

    //     let create_subject_body = generate_subject(&baseline).await;

    //     let create_workgroup_params = Some(json!({
    //         "subject_id": format!("did:prvd:{}", &create_subject_body.id),
    //         "description": "An example of the request body for workgroup creation",
    //         "name": "Example workgroup",
    //         "network_id": "07102258-5e49-480e-86af-6d0c3260827d",
    //         "type": "baseline",
    //         "security_policies": [],
    //         "admins": [
    //             format!("did:prvd:{}", &create_subject_body.id),
    //         ],
    //     }));

    //     let create_workgroup_res = baseline.create_workgroup(create_workgroup_params).await.expect("create workgroup response");

    //     let create_workgroup_body = create_workgroup_res.json::<Workgroup>().await.expect("create workgroup body");

    //     let another_subject_body = generate_subject(&baseline).await;

    //     // then probably pass that as a param in body - the swaggerhub is incomplete
    // }

    // #[tokio::test]
    // async fn create_object() {}

    // #[tokio::test]
    // async fn update_object() {}

    // #[tokio::test]
    // async fn get_state() {}

    // #[tokio::test]
    // async fn get_state_objects() {}
}

// create workgroup helper