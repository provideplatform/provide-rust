use crate::api::client::{ApiClient, Params, Response};
pub use crate::models::baseline::*;
use async_trait::async_trait;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "baseline.provide.network";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait Baseline {
    fn factory(token: &str) -> Self;

    async fn issue_verifiable_credential(&self, params: Params) -> Response;

    async fn create_public_workgroup_invite(&self, params: Params) -> Response;

    async fn get_bpi_accounts(&self) -> Response;

    async fn get_bpi_account(&self, account_id: &str) -> Response;

    async fn create_bpi_account(&self, params: Params) -> Response;

    async fn create_message(&self, params: Params) -> Response;

    async fn get_subjects(&self) -> Response;

    async fn get_subject(&self, subject_id: &str) -> Response;

    async fn create_subject(&self, params: Params) -> Response;

    async fn update_subject(&self, subject_id: &str, params: Params) -> Response;

    async fn get_subject_accounts(&self, subject_id: &str) -> Response;

    async fn get_subject_account(&self, subject_id: &str, account_id: &str) -> Response;

    async fn create_subject_account(&self, subject_id: &str, params: Params) -> Response;

    async fn update_subject_account(
        &self,
        subject_id: &str,
        account_id: &str,
        params: Params,
    ) -> Response;

    async fn get_mappings(&self) -> Response;

    async fn create_mapping(&self, params: Params) -> Response;

    async fn update_mapping(&self, mapping_id: &str, params: Params) -> Response;

    async fn delete_mapping(&self, mapping_id: &str) -> Response;

    async fn update_config(&self, params: Params) -> Response;

    async fn get_workflows(&self, params: Params) -> Response;

    async fn get_workflow(&self, workflow_id: &str) -> Response;

    async fn create_workflow(&self, params: Params) -> Response;

    async fn update_workflow(&self, workflow_id: &str, params: Params) -> Response;

    async fn deploy_workflow(&self, workflow_id: &str) -> Response;

    async fn delete_workflow(&self, workflow_id: &str) -> Response;

    async fn get_workgroups(&self) -> Response;

    async fn get_workgroup(&self, workgroup_id: &str) -> Response;

    async fn create_workgroup(&self, params: Params) -> Response;

    async fn update_workgroup(&self, workgroup_id: &str, params: Params) -> Response;

    async fn fetch_worksteps(&self, workflow_id: &str) -> Response;

    async fn get_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response;

    async fn create_workstep(&self, workflow_id: &str, params: Params) -> Response;

    async fn update_workstep(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        params: Params,
    ) -> Response;

    async fn delete_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response;

    async fn execute_workstep(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        params: Params,
    ) -> Response;
}

#[async_trait]
impl Baseline for ApiClient {
    fn factory(token: &str) -> Self {
        let scheme = std::env::var("BASELINE_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("BASELINE_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("BASELINE_API_PATH").unwrap_or(String::from(DEFAULT_PATH));

        return ApiClient::new(&scheme, &host, &path, token);
    }

    async fn issue_verifiable_credential(&self, params: Params) -> Response {
        return self.post("credentials", params, None).await;
    }

    async fn create_public_workgroup_invite(&self, params: Params) -> Response {
        return self.post("pub/invite", params, None).await;
    }

    async fn get_bpi_accounts(&self) -> Response {
        return self.get("bpi_accounts", None, None).await;
    }

    async fn get_bpi_account(&self, account_id: &str) -> Response {
        let uri = format!("bpi_accounts/{}", account_id);
        return self.get(&uri, None, None).await;
    }

    async fn create_bpi_account(&self, params: Params) -> Response {
        return self.post("bpi_accounts", params, None).await;
    }

    async fn create_message(&self, params: Params) -> Response {
        return self.post("protocol_messages", params, None).await;
    }

    async fn get_subjects(&self) -> Response {
        return self.get("subjects", None, None).await;
    }

    async fn get_subject(&self, subject_id: &str) -> Response {
        let uri = format!("subjects/{}", subject_id);
        return self.get(&uri, None, None).await;
    }

    async fn create_subject(&self, params: Params) -> Response {
        return self.post("subjects", params, None).await;
    }

    async fn update_subject(&self, subject_id: &str, params: Params) -> Response {
        let uri = format!("subjects/{}", subject_id);
        return self.put(&uri, params, None).await;
    }

    async fn get_subject_accounts(&self, subject_id: &str) -> Response {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.get(&uri, None, None).await;
    }

    async fn get_subject_account(&self, subject_id: &str, account_id: &str) -> Response {
        let uri = format!("subjects/{}/accounts/{}", subject_id, account_id);
        return self.get(&uri, None, None).await;
    }

    async fn create_subject_account(&self, subject_id: &str, params: Params) -> Response {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.post(&uri, params, None).await;
    }

    async fn update_subject_account(
        &self,
        subject_id: &str,
        account_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!("subjects/{}/accounts/{}", subject_id, account_id);
        return self.put(&uri, params, None).await;
    }

    async fn get_mappings(&self) -> Response {
        return self.get("mappings", None, None).await;
    }

    async fn create_mapping(&self, params: Params) -> Response {
        return self.post("mappings", params, None).await;
    }

    async fn update_mapping(&self, mapping_id: &str, params: Params) -> Response {
        let uri = format!("mappings/{}", mapping_id);
        return self.put(&uri, params, None).await;
    }

    async fn delete_mapping(&self, mapping_id: &str) -> Response {
        let uri = format!("mappings/{}", mapping_id);
        return self.delete(&uri, None, None).await;
    }

    async fn update_config(&self, params: Params) -> Response {
        return self.put("config", params, None).await;
    }

    async fn get_workflows(&self, params: Params) -> Response {
        return self.get("workflows", params, None).await;
    }

    async fn get_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}", workflow_id);
        return self.get(&uri, None, None).await;
    }

    async fn create_workflow(&self, params: Params) -> Response {
        return self.post("workflows", params, None).await;
    }

    async fn update_workflow(&self, workflow_id: &str, params: Params) -> Response {
        let uri = format!("workflows/{}", workflow_id);
        return self.put(&uri, params, None).await;
    }

    async fn deploy_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}/deploy", workflow_id);
        return self.post(&uri, None, None).await;
    }

    async fn delete_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}", workflow_id);
        return self.delete(&uri, None, None).await;
    }

    async fn get_workgroups(&self) -> Response {
        return self.get("workgroups", None, None).await;
    }

    async fn get_workgroup(&self, workgroup_id: &str) -> Response {
        let uri = format!("workgroups/{}", workgroup_id);
        return self.get(&uri, None, None).await;
    }

    async fn create_workgroup(&self, params: Params) -> Response {
        return self.post("workgroups", params, None).await;
    }

    async fn update_workgroup(&self, workgroup_id: &str, params: Params) -> Response {
        let uri = format!("workgroups/{}", workgroup_id);
        return self.put(&uri, params, None).await;
    }

    async fn fetch_worksteps(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}/worksteps", workflow_id);
        return self.get(&uri, None, None).await;
    }

    async fn get_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.get(&uri, None, None).await;
    }

    async fn create_workstep(&self, workflow_id: &str, params: Params) -> Response {
        let uri = format!("workflows/{}/worksteps", workflow_id);
        return self.post(&uri, params, None).await;
    }

    async fn update_workstep(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.put(&uri, params, None).await;
    }

    async fn delete_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.delete(&uri, None, None).await;
    }

    async fn execute_workstep(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!(
            "workflows/{}/worksteps/{}/execute",
            workflow_id, workstep_id
        );
        return self.post(&uri, params, None).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ident::{Application, AuthenticateResponse, Ident, Organization, Token};
    use crate::api::nchain::{Account, Contract, NChain};
    use crate::api::vault::{Vault, VaultContainer, VaultKey};
    use fake::faker::internet::en::{FreeEmail, Password};
    use fake::faker::name::en::{FirstName, LastName, Name};
    use fake::Fake;
    use serde_json::{json, Value};
    use std::io::Write;
    use std::process::Command;
    use tokio::time::{self, Duration};

    const ROPSTEN_NETWORK_ID: &str = "66d44f30-9092-4182-a3c4-bc02736d6ae5";

    async fn _create_workflow(
        baseline: &ApiClient,
        params: Value,
        expected_status: u16,
    ) -> Workflow {
        let create_workflow_res = baseline
            .create_workflow(Some(params))
            .await
            .expect("create workflow response");
        assert_eq!(
            create_workflow_res.status(),
            expected_status,
            "create workflow response body: {:?}",
            create_workflow_res.json::<Value>().await.unwrap()
        );

        if expected_status == 201 {
            create_workflow_res
                .json::<Workflow>()
                .await
                .expect("create workflow body")
        } else {
            Workflow::default()
        }
    }

    async fn _create_workstep(
        baseline: &ApiClient,
        workflow_id: &str,
        params: Value,
        expected_status: u16,
    ) -> Workstep {
        let create_workstep_res = baseline
            .create_workstep(workflow_id, Some(params))
            .await
            .expect("create workstep response");
        assert_eq!(
            create_workstep_res.status(),
            expected_status,
            "create workstep response body: {:?}",
            create_workstep_res.json::<Value>().await.unwrap()
        );

        if expected_status == 201 {
            create_workstep_res
                .json::<Workstep>()
                .await
                .expect("create workstep body")
        } else {
            Workstep::default()
        }
    }

    // add timeout
    async fn _deploy_workflow(baseline: &ApiClient, workflow_id: &str, expected_status: u16) {
        let deploy_workflow_res = baseline
            .deploy_workflow(workflow_id)
            .await
            .expect("deploy workflow response");
        assert_eq!(
            deploy_workflow_res.status(),
            expected_status,
            "deploy workflow response body: {:?}",
            deploy_workflow_res.json::<Value>().await.unwrap()
        );

        if expected_status == 202 {
            let mut interval = time::interval(Duration::from_secs(10));

            let mut deployed_worksteps_status = false;

            while deployed_worksteps_status != true {
                let fetch_worksteps_res = baseline
                    .fetch_worksteps(workflow_id)
                    .await
                    .expect("fetch worksteps response");
                let fetch_worksteps_body = fetch_worksteps_res
                    .json::<Vec<Workstep>>()
                    .await
                    .expect("fetch worksteps body");

                let mut count = 0;
                for idx in 0..fetch_worksteps_body.len() {
                    let workstep = &fetch_worksteps_body[idx];
                    if workstep.status == "deployed" {
                        count += 1;
                    }
                }

                if count == fetch_worksteps_body.len() {
                    deployed_worksteps_status = true
                } else {
                    interval.tick().await;
                }
            }
            assert!(deployed_worksteps_status);

            let mut deployed_workflow_status = false;

            while deployed_workflow_status != true {
                let get_workflow_res = baseline
                    .get_workflow(workflow_id)
                    .await
                    .expect("get workflow response");
                let get_workflow_body = get_workflow_res
                    .json::<Workflow>()
                    .await
                    .expect("get workflow body");

                if get_workflow_body.status == "deployed" {
                    deployed_workflow_status = true;
                } else {
                    interval.tick().await;
                }
            }
            assert!(deployed_workflow_status);
        }
    }

    async fn generate_baseline_application(ident: &ApiClient, user_id: &str) -> Application {
        let application_data = json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": user_id,
            "name": format!("{} application", Name().fake::<String>()),
            "description": "Some application description",
            "type": "baseline",
            "hidden": false,
            "config": {
                "onboarding_complete": true,
            }
        });

        let create_application_res = ident
            .create_application(Some(application_data))
            .await
            .expect("generate application response");
        assert_eq!(create_application_res.status(), 201);

        return create_application_res
            .json::<Application>()
            .await
            .expect("create application body");
    }

    async fn generate_baseline_organization(ident: &ApiClient, user_id: &str) -> Organization {
        let create_organization_params = Some(json!({
            "name": format!("{} organization", Name().fake::<String>()).chars().filter(|c| !c.is_whitespace()).collect::<String>().replace("'", ""),
            "description": "Organization for testing",
            "user_id": user_id,
            "metadata": {
                "hello": "world",
                "arbitrary": "input",
            },
        }));
        let create_organization_res = ident
            .create_organization(create_organization_params)
            .await
            .expect("create organization response");
        assert_eq!(create_organization_res.status(), 201);

        return create_organization_res
            .json::<Organization>()
            .await
            .expect("generate organization body");
    }

    #[tokio::test]
    async fn _setup() {
        let skip_setup =
            std::env::var("SKIP_SETUP").unwrap_or(String::from("")) == "true";
        if skip_setup {
            assert!(true);
            return;
        }

        // create user
        let mut ident: ApiClient = Ident::factory("");
        let user_email = Some(FreeEmail().fake::<String>());
        let user_password = Some(Password(8..15).fake::<String>());
        let user_data = Some(json!({
            "first_name": FirstName().fake::<String>(),
            "last_name": LastName().fake::<String>(),
            "email": &user_email,
            "password": &user_password,
        }));
        let create_user_res = ident
            .create_user(user_data)
            .await
            .expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        // authenticate user
        let params = Some(json!({
            "email": &user_email,
            "password": &user_password,
            "scope": "offline_access",
        }));
        let authenticate_res = ident
            .authenticate(params)
            .await
            .expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);
        let authentication_res_body = authenticate_res
            .json::<AuthenticateResponse>()
            .await
            .expect("authentication response body");
        let user_access_token = match authentication_res_body.token.access_token {
            Some(tkn) => tkn,
            None => panic!("user access token not found"),
        };
        let user_refresh_token = match authentication_res_body.token.refresh_token {
            Some(tkn) => tkn,
            None => panic!("user refresh token not found"),
        };

        ident.token = user_access_token.to_string();

        // create organization
        let create_organization_body =
            generate_baseline_organization(&ident, &authentication_res_body.user.id).await;
        let organization_authorization_params = json!({
            "organization_id": &create_organization_body.id,
            "scope": "offline_access",
        });
        let organization_authorization_res = ident
            .organization_authorization(Some(organization_authorization_params))
            .await
            .expect("organization authorization response");
        assert_eq!(organization_authorization_res.status(), 201);
        let organization_auth_body = organization_authorization_res
            .json::<Token>()
            .await
            .expect("organization authorization body");
        let org_access_token = match organization_auth_body.access_token {
            Some(tkn) => tkn,
            None => panic!("organization access token not found"),
        };
        let org_refresh_token = match organization_auth_body.refresh_token {
            Some(tkn) => tkn,
            None => panic!("organization refresh token not found"),
        };

        // create application
        let create_application_body =
            generate_baseline_application(&ident, &authentication_res_body.user.id).await;
        let application_authorization_params = json!({
            "application_id": &create_application_body.id,
            "scope": "offline_access",
        });
        let application_authorization_res = ident
            .application_authorization(Some(application_authorization_params))
            .await
            .expect("application authorization response");
        assert_eq!(application_authorization_res.status(), 201);
        let application_auth_body = application_authorization_res
            .json::<Token>()
            .await
            .expect("application authorization body");
        let app_access_token = match application_auth_body.access_token {
            Some(tkn) => tkn,
            None => panic!("application access toke not found"),
        };

        // associate application organization
        ident.token = app_access_token.to_string();

        let associate_application_org_params = json!({
            "organization_id": &create_organization_body.id,
        });
        let associate_application_org_res = ident
            .create_application_organization(
                &create_application_body.id,
                Some(associate_application_org_params),
            )
            .await
            .expect("create application organization response");
        assert_eq!(associate_application_org_res.status(), 204);

        // get shuttle registry contract
        let registry_contracts_res = ident.client.get("https://s3.amazonaws.com/static.provide.services/capabilities/provide-capabilities-manifest.json").send().await.expect("get registry contracts response");
        let registry_contracts = registry_contracts_res
            .json::<Value>()
            .await
            .expect("registry contracts body");
        let shuttle_contract = &registry_contracts["baseline"]["contracts"][2];

        let nchain: ApiClient = NChain::factory(&app_access_token);

        // deploy workgroup contract
        let create_account_params = json!({
            "network_id": ROPSTEN_NETWORK_ID,
        });
        let create_account_res = nchain
            .create_account(Some(create_account_params))
            .await
            .expect("create account response");
        assert_eq!(
            create_account_res.status(),
            201,
            "create account response body: {:?}",
            create_account_res.json::<Value>().await.unwrap()
        ); // FAILS HERE RARELY
        let create_account_body = create_account_res
            .json::<Account>()
            .await
            .expect("create account body");

        let baseline_registry_contract_address =
            std::env::var("BASELINE_REGISTRY_CONTRACT_ADDRESS").unwrap_or(String::from("0x"));

        let create_contract_params = json!({
            "address": &baseline_registry_contract_address,
            "params": {
                "account_id": &create_account_body.id,
                "compiled_artifact": shuttle_contract,
                "argv": [],
            },
            "name": "Shuttle",
            "network_id": ROPSTEN_NETWORK_ID,
            "type": "organization-registry",
        });
        let create_contract_res = nchain
            .create_contract(Some(create_contract_params))
            .await
            .expect("create contract response");
        assert_eq!(create_contract_res.status(), 201);

        let mut registry_contract = create_contract_res
            .json::<Contract>()
            .await
            .expect("create contract body");
        let mut interval = time::interval(Duration::from_millis(500));
        while registry_contract.address == "0x" {
            interval.tick().await;
            let get_contract_res = nchain
                .get_contract(&registry_contract.id)
                .await
                .expect("get contract response");
            assert_eq!(get_contract_res.status(), 200);
            registry_contract = get_contract_res
                .json::<Contract>()
                .await
                .expect("get contract body");
        }
        let registry_contract_address = registry_contract.address;

        let vault: ApiClient = Vault::factory(&app_access_token);

        // organization address
        let create_vault_params = json!({
            "name": format!("{} vault", Name().fake::<String>()),
            "description": "Some vault description",
        });
        let create_vault_res = vault
            .create_vault(Some(create_vault_params))
            .await
            .expect("create vault response");
        assert_eq!(create_vault_res.status(), 201);
        let create_vault_body = create_vault_res
            .json::<VaultContainer>()
            .await
            .expect("create vault body");
        let create_key_params = json!({
            "type": "symmetric",
            "usage": "encrypt/decrypt",
            "spec": "secp256k1",
            "name": format!("{} key", Name().fake::<String>()),
            "description": "Some key description",
        });
        let create_key_res = vault
            .create_key(&create_vault_body.id, Some(create_key_params))
            .await
            .expect("create key response");
        assert_eq!(create_key_res.status(), 201);
        let create_key_body = create_key_res
            .json::<VaultKey>()
            .await
            .expect("create key body");
        let org_address = match create_key_body.address {
            Some(string) => string,
            None => panic!("address from organization key not found"),
        };

        // json config file
        // TODO: refactor to use memory
        let json_config_params = json!({
            "user_access_token": &user_access_token,
            "user_refresh_token": &user_refresh_token,
            "org_access_token": &org_access_token,
            "org_refresh_token": &org_refresh_token,
            "org_id": &create_organization_body.id,
            "org_name": &create_organization_body.name,
            "app_access_token": &app_access_token,
            "app_id": &create_application_body.id,
        });
        serde_json::to_writer_pretty(
            std::fs::File::create(".test-config.tmp.json")
                .expect("baseline integration suite setup json config"),
            &json_config_params,
        )
        .expect("write json");

        let invoke_prvd_cli = std::env::var("INVOKE_PRVD_CLI")
            .unwrap_or(String::from("true"))
            .to_lowercase()
            == "true";
        if invoke_prvd_cli {
            // check if prvd cli is installed
            let prvd_cli_cmd = Command::new("sh")
                .arg("-c")
                .arg("prvd")
                .output()
                .expect("provide cli install check");
            if !prvd_cli_cmd.status.success() {
                panic!("Provide cli not installed. Please install to run the baseline integration test SUITE")
                // link to cli?
            }

            // yaml config file
            let config_file_contents = format!(
                "access-token: {}\nrefresh-token: {}\n{}:\n  api-token: {}\n",
                &user_access_token,
                &user_refresh_token,
                &create_application_body.id,
                &app_access_token
            );
            let cwd = match std::env::current_dir() {
                Ok(path) => path
                    .into_os_string()
                    .into_string()
                    .expect("current working directory"),
                Err(v) => panic!("{:?}", v),
            };
            let config_file_name = format!("{}/.local-baseline-test-config.tmp.yaml", cwd);
            let mut config_file =
                std::fs::File::create(&config_file_name).expect("prvd cli config file name");
            write!(config_file, "{}", config_file_contents).expect("config contents");

            // start command & environment
            let run_env = format!("LOG_LEVEL=TRACE IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http NCHAIN_API_HOST=localhost:8084 NCHAIN_API_SCHEME=http VAULT_API_HOST=localhost:8082 VAULT_API_SCHEME=http PROVIDE_ORGANIZATION_REFRESH_TOKEN={}", &org_refresh_token);

            let mut run_cmd = String::from("prvd baseline stack start");
            run_cmd += &format!(" --api-endpoint={}", "http://localhost:8086");
            run_cmd += &format!(" --config={}", &config_file_name);
            run_cmd += &format!(
                " --ident-host={}",
                std::env::var("IDENT_API_HOST").unwrap_or(String::from("localhost:8081"))
            );
            run_cmd += &format!(
                " --ident-scheme={}",
                std::env::var("IDENT_API_SCHEME").unwrap_or(String::from("http"))
            );
            run_cmd += &format!(" --messaging-endpoint={}", "nats://localhost:4223");
            run_cmd += &format!(" --name=\"{}\"", &create_organization_body.name);
            run_cmd += &format!(" --nats-auth-token={}", "testtoken");
            run_cmd += &format!(" --nats-port={}", "4223");
            run_cmd += &format!(" --nats-ws-port={}", "4224");
            run_cmd += &format!(
                " --nchain-host={}",
                std::env::var("NCHAIN_API_HOST").unwrap_or(String::from("localhost:8084"))
            );
            run_cmd += &format!(
                " --nchain-scheme={}",
                std::env::var("NCHAIN_API_SCHEME").unwrap_or(String::from("http"))
            );
            run_cmd += &format!(" --nchain-network-id={}", ROPSTEN_NETWORK_ID);
            run_cmd += &format!(" --organization={}", &create_organization_body.id);
            run_cmd += &format!(" --organization-address={}", &org_address);
            run_cmd += &format!(" --organization-refresh-token={}", &org_refresh_token);
            run_cmd += &format!(" --port={}", "8085");
            run_cmd += &format!(
                " --privacy-host={}",
                std::env::var("PRIVACY_API_HOST").unwrap_or(String::from("localhost:8083"))
            );
            run_cmd += &format!(
                " --privacy-scheme={}",
                std::env::var("PRIVACY_API_SCHEME").unwrap_or(String::from("http"))
            );
            run_cmd += &format!(
                " --registry-contract-address={}",
                &registry_contract_address
            );
            run_cmd += &format!(" --redis-hostname={}-redis", &create_organization_body.name);
            run_cmd += &format!(" --redis-port={}", "6380");
            run_cmd += &format!(" --sor={}", "ephemeral");
            run_cmd += &format!(
                " --vault-host={}",
                std::env::var("VAULT_API_HOST").unwrap_or(String::from("localhost:8082"))
            );
            run_cmd += &format!(" --vault-refresh-token={}", &org_refresh_token);
            run_cmd += &format!(
                " --vault-scheme={}",
                std::env::var("VAULT_API_SCHEME").unwrap_or(String::from("http"))
            );
            run_cmd += &format!(" --workgroup={}", &create_application_body.id);
            run_cmd += &format!(
                " --postgres-hostname={}-postgres",
                &create_organization_body.name
            );
            run_cmd += &format!(" --postgres-port={}", "5433");

            let key_str = r"\n-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqU/GXp8MqmugQyRk5FUF\nBvlJt1/h7L3Crzlzejz/OxriZdq/lBNQW9S1kzGc7qjXprZ1Kg3zP6irr6wmvP0W\nYBGltWs2cWUAmxh0PSxuKdT/OyL9w+rjKLh4yo3ex6DX3Ij0iP01Ej2POe5WrPDS\n8j6LT0s4HZ1FprL5h7RUQWV3cO4pF+1kl6HlBpNzEQzocW9ig4DNdSeUENARHWoC\nixE1gFYo9RXm7acqgqCk3ihdJRIbO4e/m1aZq2mvAFK+yHTIWBL0p5PF0Fe8zcWd\nNeEATYB+eRdNJ3jjS8447YrcbQcBQmhFjk8hbCnc3Rv3HvAapk8xDFhImdVF1ffD\nFwIDAQAB\n-----END PUBLIC KEY-----";
            run_cmd += &format!(" --jwt-signer-public-key='{}'", &key_str);

            let localhost_regex =
                regex::Regex::new(r"localhost").expect("localhost regex expression");
            run_cmd = localhost_regex
                .replace_all(&run_cmd, "host.docker.internal")
                .to_string();
            let baseline_cmd = format!("{} {}", run_env, run_cmd);

            Command::new("sh")
                .arg("-c")
                .arg(&baseline_cmd)
                .spawn()
                .expect("baseline tests init process"); // attach to some sort of log level?

            // FIXME-- refactor ApiClient::new to not default to scheme://host/path but instead scheme::/hostpath
            let mut baseline_status_client = ApiClient::new("", "", "", "");
            baseline_status_client.set_base_url(&format!(
                "{}://{}",
                std::env::var("BASELINE_API_SCHEME").expect("baseline api scheme"),
                std::env::var("BASELINE_API_HOST").expect("baseline api host")
            ));

            let mut baseline_container_status = String::from("");

            while baseline_container_status == "" {
                baseline_container_status =
                    match baseline_status_client.get("status", None, None).await {
                        Ok(res) => res.status().to_string(),
                        Err(_) => String::from(""),
                    };

                interval.tick().await;
            }

            assert_eq!(baseline_container_status, "204 No Content");
        } else {
            let baseline: ApiClient = Baseline::factory(&org_access_token);

            let seconds = time::Duration::from_secs(10);
            std::thread::sleep(seconds);

            let update_config_params = json!({
                "network_id": ROPSTEN_NETWORK_ID,
                "organization_address": &registry_contract_address,
                "organization_id": &create_organization_body.id,
                "organization_refresh_token": &org_refresh_token,
                "registry_contract_address": &registry_contract_address,
                "workgroup_id": &create_application_body.id,
            });

            let update_config_res = baseline
                .update_config(Some(update_config_params))
                .await
                .expect("update config response");
            assert_eq!(update_config_res.status(), 204);
        }
    }

    // #[tokio::test]
    // async fn issue_verifiable_credential() {

    // }

    // #[tokio::test]
    // async fn create_public_workgroup_invite() {

    // }

    // #[tokio::test]
    // async fn get_bpi_accounts() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let get_bpi_accounts_res = baseline.get_bpi_accounts().await.expect("get bpi accounts response");
    //     assert_eq!(get_bpi_accounts_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn get_bpi_account() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_bpi_account_params = json!({
    //         "owners": [
    //             "did:prvd:7cb23e2b-07ed-4562-8afb-73955f8f17c5"
    //         ],
    //         "security_policies": [
    //             {
    //             "type": "AuthenticationPolicy",
    //             "reference": "https://example.com/policies/authentication-policy.json"
    //             }
    //         ],
    //         "nonce": 4114,
    //         "workflows": {
    //             "$ref": "#/components/schemas/WorkflowInstance"
    //         },
    //     });

    //     let create_bpi_account_res = baseline.create_bpi_account(Some(create_bpi_account_params)).await.expect("create bpi account response");
    //     assert_eq!(create_bpi_account_res.status(), 201);

    //     let create_bpi_account_body = create_bpi_account_res.json::<BpiAccount>().await.expect("create bpi account body");

    //     let get_bpi_account_res = baseline.get_bpi_account(&create_bpi_account_body.id).await.expect("get bpi account response");
    //     assert_eq!(get_bpi_account_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_bpi_account() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_bpi_account_params = json!({
    //         "owners": [
    //             "did:prvd:7cb23e2b-07ed-4562-8afb-73955f8f17c5"
    //         ],
    //         "security_policies": [
    //             {
    //             "type": "AuthenticationPolicy",
    //             "reference": "https://example.com/policies/authentication-policy.json"
    //             }
    //         ],
    //         "nonce": 4114,
    //         "workflows": {
    //             "$ref": "#/components/schemas/WorkflowInstance"
    //         },
    //     });

    //     let create_bpi_account_res = baseline.create_bpi_account(Some(create_bpi_account_params)).await.expect("create bpi account response");
    //     assert_eq!(create_bpi_account_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn create_message() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_message_params = json!({
    //         "proof": "string",
    //         "type": "string",
    //         "witness": {},
    //     });

    //     let create_message_res = baseline.create_message(Some(create_message_params)).await.expect("create message response");
    //     assert_eq!(create_message_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn get_subjects() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let get_subjects_res = baseline.get_subjects().await.expect("get subjects response");
    //     assert_eq!(get_subjects_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn get_subject() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_subject_params = json!({
    //         "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
    //         "credentials": [],
    //         "description": "Organization for testing",
    //         "metadata": {},
    //         "name": "ACME Inc.",
    //         "type": "Organization",
    //     });

    //     let create_subject_res = baseline.create_subject(Some(create_subject_res)).await.expect("create subject response");
    //     assert_eq!(create_subject_res.status(), 201);

    //     let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

    //     let get_subject_res = baseline.get_subject(&create_subject_body.id).await.expect("get subject response");
    //     assert_eq!(get_subject_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_subject() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    // let create_subject_params = json!({
    //     "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
    //     "credentials": [],
    //     "description": "Organization for testing",
    //     "metadata": {},
    //     "name": "ACME Inc.",
    //     "type": "Organization",
    // });

    // let create_subject_res = baseline.create_subject(Some(create_subject_res)).await.expect("create subject response");
    // assert_eq!(create_subject_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn update_subject() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_subject_params = json!({
    //         "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
    //         "credentials": [],
    //         "description": "Organization for testing",
    //         "metadata": {},
    //         "name": "ACME Inc.",
    //         "type": "Organization",
    //     });

    //     let create_subject_res = baseline.create_subject(Some(create_subject_res)).await.expect("create subject response");
    //     assert_eq!(create_subject_res.status(), 201);

    //     let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

    //     let update_subject_params = json!({
    //         "description": "an updated subject description",
    //     });

    //     let update_subject_res = baseline.update_subject(&create_subject_body.id, Some(update_subject_params)).await.expect("update subject response");
    //     assert_eq!(update_subject_res.status(), 204);
    // }

    // #[tokio::test]
    // async fn get_subject_accounts() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_subject_params = json!({
    //         "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
    //         "credentials": [],
    //         "description": "Organization for testing",
    //         "metadata": {},
    //         "name": "ACME Inc.",
    //         "type": "Organization",
    //     });

    //     let create_subject_res = baseline.create_subject(Some(create_subject_res)).await.expect("create subject response");
    //     assert_eq!(create_subject_res.status(), 201);

    //     let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

    //     let get_subject_accounts_res = baseline.get_subject_accounts(&create_subject_body.id).await.expect("get subject accounts response");
    //     assert_eq!(get_subject_accounts_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn get_subject_account() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_subject_params = json!({
    //         "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
    //         "credentials": [],
    //         "description": "Organization for testing",
    //         "metadata": {},
    //         "name": "ACME Inc.",
    //         "type": "Organization",
    //     });

    //     let create_subject_res = baseline.create_subject(Some(create_subject_res)).await.expect("create subject response");
    //     assert_eq!(create_subject_res.status(), 201);

    //     let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

    //     let create_subject_account_params = json!({
    //         "@context": [],
    //         "bpi_account_ids": [
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
    //         "subject_id": "did:prvd:93229a14-5e13-4c45-8352-3ad9948b8ae3",
    //         "security_policies": {
    //             "type": "AuthenticationPolicy",
    //             "reference": ""
    //         }
    //     });

    //     let create_subject_account_res = baseline.create_subject_account(&create_subject_body.id, Some(create_subject_account_params)).await.expect("create subject account response");
    //     assert_eq!(create_subject_account_res.status(), 201);

    //     let create_subject_account_body = create_subject_account_res.json::<SubjectAccount>().await.expect("create subject account body");

    //     let get_subject_account_res = baseline.get_subject_account(&create_subject_body.id, &create_subject_account_body.id).await.expect("get subject account response");
    //     assert_eq!(get_subject_account_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_subject_account() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
    //         .expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_subject_params = json!({
    //         "wallet_id": "99c404e9-fe10-4ca7-b787-d5943d03591c",
    //         "credentials": [],
    //         "description": "Organization for testing",
    //         "metadata": {},
    //         "name": "ACME Inc.",
    //         "type": "Organization",
    //     });

    //     let create_subject_res = baseline.create_subject(Some(create_subject_res)).await.expect("create subject response");
    //     assert_eq!(create_subject_res.status(), 201);

    //     let create_subject_body = create_subject_res.json::<Subject>().await.expect("create subject body");

    //     let create_subject_account_params = json!({
    //         "@context": [],
    //         "bpi_account_ids": [
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
    //         "subject_id": "did:prvd:93229a14-5e13-4c45-8352-3ad9948b8ae3",
    //         "security_policies": {
    //             "type": "AuthenticationPolicy",
    //             "reference": ""
    //         }
    //     });

    //     let create_subject_account_res = baseline.create_subject_account(&create_subject_body.id, Some(create_subject_account_params)).await.expect("create subject account response");
    //     assert_eq!(create_subject_account_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn update_subject_account() {

    // }

    #[tokio::test]
    async fn get_mappings() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let get_mappings_res = baseline
            .get_mappings()
            .await
            .expect("get mappings response");
        assert_eq!(get_mappings_res.status(), 200);
    }

    #[tokio::test]
    async fn create_mapping() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_mapping_params = json!({
          "name": format!("{} Mapping", Name().fake::<String>()),
          "type": "mapping_type",
          "workgroup_id": &app_id,
          "models": [
            {
              "description": "test model",
              "primary_key": "id",
              "type": "test",
              "fields": [
                {
                  "is_primary_key": true,
                  "name": "id",
                  "type": "string"
                }
              ]
            }
          ]
        });

        let create_mapping_res = baseline
            .create_mapping(Some(create_mapping_params))
            .await
            .expect("create mapping response");
        assert_eq!(
            create_mapping_res.status(),
            201,
            "create mapping response body: {:?}",
            create_mapping_res.json::<Value>().await.unwrap()
        );
    }

    #[tokio::test]
    async fn update_mapping() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_mapping_params = json!({
          "name": format!("{} Mapping", Name().fake::<String>()),
          "type": "mapping_type",
          "workgroup_id": &app_id,
          "models": [
            {
              "description": "test model",
              "primary_key": "id",
              "type": "test",
              "fields": [
                {
                  "is_primary_key": true,
                  "name": "id",
                  "type": "string"
                }
              ]
            }
          ]
        });

        let create_mapping_res = baseline
            .create_mapping(Some(create_mapping_params))
            .await
            .expect("create mapping response");
        assert_eq!(
            create_mapping_res.status(),
            201,
            "create mapping response body: {:?}",
            create_mapping_res.json::<Value>().await.unwrap()
        );

        let create_mapping_body = create_mapping_res
            .json::<Mapping>()
            .await
            .expect("create mapping body");

        let updated_description = format!("{} description", Name().fake::<String>());
        let updated_model = json!({
            "type": "PurchaseOrder",
            "fields": [
                {
                    "name": "id",
                    "is_primary_key": true,
                },
                {
                    "name": "id",
                    "is_primary_key": false,
                },
            ],
            "primary_key": "id",
        });

        let update_mapping_params = json!({
            "description": &updated_description,
            "models": [
               updated_model,
            ],
        });

        let update_mapping_res = baseline
            .update_mapping(&create_mapping_body.id, Some(update_mapping_params))
            .await
            .expect("update mapping response");
        assert_eq!(update_mapping_res.status(), 204);

        // let get_updated_mapping_res = baseline
        //     .get_mappings()
        //     .await
        //     .expect("get updated mapping response");
        // assert_eq!(get_updated_mapping_res.status(), 200);

        // let updated_model = &get_updated_mapping_res.json::<Vec<Mapping>>().await.unwrap().to_owned()[0].models[0];
        // println!(
        //     "updated model: {:?}",
        //     serde_json::to_string_pretty(updated_model).unwrap()
        // );
    }

    #[tokio::test]
    async fn delete_mapping() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_mapping_params = json!({
          "name": format!("{} Mapping", Name().fake::<String>()),
          "type": "mapping_type",
          "workgroup_id": &app_id,
          "models": [
            {
              "description": "test model",
              "primary_key": "id",
              "type": "test",
              "fields": [
                {
                  "is_primary_key": true,
                  "name": "id",
                  "type": "string"
                }
              ]
            }
          ]
        });

        let create_mapping_res = baseline
            .create_mapping(Some(create_mapping_params))
            .await
            .expect("create mapping response");
        assert_eq!(
            create_mapping_res.status(),
            201,
            "create mapping response body: {:?}",
            create_mapping_res.json::<Value>().await.unwrap()
        );

        let create_mapping_body = create_mapping_res
            .json::<Mapping>()
            .await
            .expect("create mapping body");

        let delete_mapping_res = baseline
            .delete_mapping(&create_mapping_body.id)
            .await
            .expect("delete mapping response");
        assert_eq!(delete_mapping_res.status(), 204);
    }

    // #[tokio::test]
    // async fn update_config() {}

    #[tokio::test]
    async fn get_workflows() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let get_workflows_params = json!({
            "workgroup_id": &app_id, // i dont think this is necessary, its org scoped
        });

        let get_workflows_res = baseline
            .get_workflows(Some(get_workflows_params))
            .await
            .expect("get workflows response");
        assert_eq!(get_workflows_res.status(), 200);
    }

    #[tokio::test]
    async fn get_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let get_workflow_res = baseline
            .get_workflow(&create_workflow_body.id)
            .await
            .expect("get workflow response");
        assert_eq!(get_workflow_res.status(), 200);
    }

    #[tokio::test]
    async fn create_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        // test all possible params
        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let _ = _create_workflow(&baseline, create_workflow_params, 201).await;
    }

    #[tokio::test]
    async fn create_workflow_instance() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

        let create_workflow_instance_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "workflow_id": &create_workflow_body.id,
        });

        let _ = _create_workflow(&baseline, create_workflow_instance_params, 201).await;
    }

    #[tokio::test]
    async fn create_workflow_instance_worksteps() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

        let create_workflow_instance_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "workflow_id": &create_workflow_body.id,
        });

        // FIXME: this type is wrong, should be workflowinstance instead of workflow
        let create_workflow_instance_body =
            _create_workflow(&baseline, create_workflow_instance_params, 201).await;

        let fetch_workflow_instance_worksteps_res = baseline
            .fetch_worksteps(&create_workflow_instance_body.id)
            .await
            .expect("fetch workflow instance worksteps response");
        assert_eq!(fetch_workflow_instance_worksteps_res.status(), 200);

        let fetch_workflow_instance_worksteps_body = fetch_workflow_instance_worksteps_res
            .json::<Vec<WorkstepInstance>>()
            .await
            .expect("fetch workflow instance worksteps body");

        for workstep_instance in fetch_workflow_instance_worksteps_body {
            assert_eq!(workstep_instance.status.unwrap(), "init");
        }
    }

    #[tokio::test]
    async fn create_workflow_instance_fail_on_draft_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let create_workflow_instance_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "workflow_id": &create_workflow_body.id,
        });

        let _ = _create_workflow(&baseline, create_workflow_instance_params, 422).await;
    }

    #[tokio::test]
    async fn update_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let update_workflow_params = json!({
            "name": format!("{} workflow", Name().fake::<String>()),
            "status": "draft",
        });

        let update_workflow_res = baseline
            .update_workflow(&create_workflow_body.id, Some(update_workflow_params))
            .await
            .expect("update workflow response");
        assert_eq!(
            update_workflow_res.status(),
            204,
            "update workflow response body: {:?}",
            update_workflow_res.json::<Value>().await.unwrap()
        );

        // let get_updated_workflow_res = baseline
        //     .get_workflow(&create_workflow_body.id)
        //     .await
        //     .expect("get updated workflow response");
        // println!(
        //     "updated workflow response body: {}",
        //     serde_json::to_string_pretty(&get_updated_workflow_res.json::<Value>().await.unwrap())
        //         .unwrap()
        // );
    }

    #[tokio::test]
    async fn deploy_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1"
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            }
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;
    }

    #[tokio::test]
    async fn deploy_workflow_fail_without_prover_on_all_worksteps() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 422).await;
    }

    #[tokio::test]
    async fn deploy_workflow_fail_without_worksteps() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 422).await;
    }

    #[tokio::test]
    async fn deploy_workflow_fail_without_finality_on_last_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 422).await;
    }

    #[tokio::test]
    async fn deploy_workflow_fail_without_version_on_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            }
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 422).await;
    }

    #[tokio::test]
    async fn update_workflow_deployed_to_deprecated() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            }
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

        let update_workflow_params = json!({
            "name": &create_workflow_body.name,
            "status": "deprecated",
        });
        let update_workflow_res = baseline
            .update_workflow(&create_workflow_body.id, Some(update_workflow_params))
            .await
            .expect("update workflow response");
        assert_eq!(update_workflow_res.status(), 204);

        // let get_updated_workflow_res = baseline
        //     .get_workflow(&create_workflow_body.id)
        //     .await
        //     .expect("get updated workflow response");
        // println!(
        //     "updated workflow response body: {}",
        //     serde_json::to_string_pretty(&get_updated_workflow_res.json::<Value>().await.unwrap())
        //         .unwrap()
        // );
    }

    #[tokio::test]
    async fn delete_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline
            .create_workflow(Some(create_workflow_params))
            .await
            .expect("create workflow response");
        assert_eq!(
            create_workflow_res.status(),
            201,
            "create workflow response body: {:?}",
            create_workflow_res.json::<Value>().await.unwrap()
        );

        let create_workflow_body = create_workflow_res
            .json::<Workflow>()
            .await
            .expect("create workflow body");

        let delete_workflow_res = baseline
            .delete_workflow(&create_workflow_body.id)
            .await
            .expect("delete workflow response");
        assert_eq!(delete_workflow_res.status(), 204);
    }

    // #[tokio::test]
    // async fn get_workgroups() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    //     let app_id_json = config_vals["app_id"].to_string();
    //     let app_id = serde_json::from_str::<String>(&app_id_json)
    //             .expect("workgroup id");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let get_workgroups_res = baseline.get_workgroups().await.expect("get workgroups response");
    //     assert_eq!(get_workgroups_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn get_workgroup() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    //     let app_id_json = config_vals["app_id"].to_string();
    //     let app_id = serde_json::from_str::<String>(&app_id_json)
    //             .expect("workgroup id");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_workgroup_params = json!({
    //         "subject_id": "did:prvd:93229a14-5e13-4c45-8352-3ad9948b8ae3",
    //         "description": "An example of the request body for workgroup creation",
    //         "name": "Example workgroup",
    //         "network_id": "07102258-5e49-480e-86af-6d0c3260827d",
    //         "type": "baseline",
    //         "security_policies": [],
    //         "admins": [
    //           "did:prvd:93229a14-5e13-4c45-8352-3ad9948b8ae3"
    //         ],
    //     });

    //     let create_workgroup_res = baseline.create_workgroup(Some(create_workgroup_params)).await.expect("create workgroup response");
    //     assert_eq!(create_workgroup_res.status(), 201);

    //     let create_workgroup_body = create_workgroup_res.json::<Workgroup>().await.expect("create workgroup body");

    //     let get_workgroup_res = baseline.get_workgroup(&create_workgroup_body.id).await.expect("get workgroup response");
    //     assert_eq!(get_workgroup_res.status(), 200);
    // }

    // #[tokio::test]
    // async fn create_workgroup() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    //     let app_id_json = config_vals["app_id"].to_string();
    //     let app_id = serde_json::from_str::<String>(&app_id_json)
    //             .expect("workgroup id");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_workgroup_params = json!({
    //         "subject_id": "did:prvd:93229a14-5e13-4c45-8352-3ad9948b8ae3",
    //         "description": "An example of the request body for workgroup creation",
    //         "name": "Example workgroup",
    //         "network_id": "07102258-5e49-480e-86af-6d0c3260827d",
    //         "type": "baseline",
    //         "security_policies": [],
    //         "admins": [
    //           "did:prvd:93229a14-5e13-4c45-8352-3ad9948b8ae3"
    //         ],
    //     });

    //     let create_workgroup_res = baseline.create_workgroup(Some(create_workgroup_params)).await.expect("create workgroup response");
    //     assert_eq!(create_workgroup_res.status(), 201);
    // }

    // #[tokio::test]
    // async fn update_workgroup() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    //     let app_id_json = config_vals["app_id"].to_string();
    //     let app_id = serde_json::from_str::<String>(&app_id_json)
    //             .expect("workgroup id");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_workgroup_params = json!({
    //         "subject_id": "did:prvd:93229a14-5e13-4c45-8352-3ad9948b8ae3",
    //         "description": "An example of the request body for workgroup creation",
    //         "name": "Example workgroup",
    //         "network_id": "07102258-5e49-480e-86af-6d0c3260827d",
    //         "type": "baseline",
    //         "security_policies": [],
    //         "admins": [
    //           "did:prvd:93229a14-5e13-4c45-8352-3ad9948b8ae3"
    //         ],
    //     });

    //     let create_workgroup_res = baseline.create_workgroup(Some(create_workgroup_params)).await.expect("create workgroup response");
    //     assert_eq!(create_workgroup_res.status(), 201);

    //     let create_workgroup_body = create_workgroup_res.json::<Workgroup>().await.expect("create workgroup body");

    //     let update_workgroup_params = json!({
    //         "description": "An updated workgroup description",
    //     });

    //     let update_workgroup_res = baseline.update_workgroup(&create_workgroup_body.id, Some(update_workgroup_params)).await.expect("update workgroup response");
    //     assert_eq!(update_workgroup_res.status(), 204);
    // }

    #[tokio::test]
    async fn fetch_worksteps() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let fetch_worksteps_res = baseline
            .fetch_worksteps(&create_workflow_body.id)
            .await
            .expect("fetch worksteps response");
        assert_eq!(fetch_worksteps_res.status(), 200);
    }

    #[tokio::test]
    async fn get_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params =
            json!({ "name": format!("{} workstep", Name().fake::<String>()) });

        let create_workstep_body = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let get_workstep_res = baseline
            .get_workstep(&create_workflow_body.id, &create_workstep_body.id)
            .await
            .expect("get workstep response");
        assert_eq!(get_workstep_res.status(), 200);
    }

    #[tokio::test]
    async fn create_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        // use all the possible params
        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
        });
        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;
    }

    #[tokio::test]
    async fn update_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_workstep_body = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let update_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "description": "an updated workstep description",
            "status": "draft",
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            }
        });

        let update_workstep_res = baseline
            .update_workstep(
                &create_workflow_body.id,
                &create_workstep_body.id,
                Some(update_workstep_params),
            )
            .await
            .expect("update workstep response");
        assert_eq!(
            update_workstep_res.status(),
            204,
            "update workstep response body: {:?}",
            update_workstep_res.json::<Value>().await.unwrap()
        );

        // let get_updated_workstep_res = baseline
        //     .get_workstep(&create_workflow_body.id, &create_workstep_body.id)
        //     .await
        //     .expect("get updated workstep response");
        // println!(
        //     "updated workstep response body: {}",
        //     serde_json::to_string_pretty(&get_updated_workstep_res.json::<Value>().await.unwrap())
        //         .unwrap()
        // );
    }

    #[tokio::test]
    async fn update_workstep_cardinality_zero_fail() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_workstep_body = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let update_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "description": "an updated workstep description",
            "status": "draft",
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
            "cardinality": 0,
        });

        let update_workstep_res = baseline
            .update_workstep(
                &create_workflow_body.id,
                &create_workstep_body.id,
                Some(update_workstep_params),
            )
            .await
            .expect("update workstep response");
        assert_eq!(
            update_workstep_res.status(),
            422,
            "update workstep response body: {:?}",
            update_workstep_res.json::<Value>().await.unwrap()
        );
    }

    #[tokio::test]
    async fn update_workstep_fail_updating_on_deployed() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_workstep_body = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let update_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "description": "an updated workstep description",
            "status": "deployed",
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            }
        });

        let update_workstep_res = baseline
            .update_workstep(
                &create_workflow_body.id,
                &create_workstep_body.id,
                Some(update_workstep_params),
            )
            .await
            .expect("update workstep response");
        assert_eq!(
            update_workstep_res.status(),
            400,
            "update workstep response body: {:?}",
            update_workstep_res.json::<Value>().await.unwrap()
        );
    }

    #[tokio::test]
    async fn update_workstep_move_cardinality_2_worksteps() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_first_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_first_workstep_body = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_first_workstep_params,
            201,
        )
        .await;

        let create_second_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_second_workstep_params,
            201,
        )
        .await;

        let update_first_workstep_up_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "cardinality": 2,
            "status": "draft",
        });

        let update_first_workstep_up_res = baseline
            .update_workstep(
                &create_workflow_body.id,
                &create_first_workstep_body.id,
                Some(update_first_workstep_up_params),
            )
            .await
            .expect("update workstep response");
        assert_eq!(
            update_first_workstep_up_res.status(),
            204,
            "update workstep response body: {:?}",
            update_first_workstep_up_res.json::<Value>().await.unwrap()
        );

        let update_second_workstep_down_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "cardinality": 1,
            "status": "draft",
        });

        let update_second_workstep_down_res = baseline
            .update_workstep(
                &create_workflow_body.id,
                &create_first_workstep_body.id,
                Some(update_second_workstep_down_params),
            )
            .await
            .expect("update workstep response");
        assert_eq!(
            update_second_workstep_down_res.status(),
            204,
            "update workstep response body: {:?}",
            update_second_workstep_down_res
                .json::<Value>()
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn update_workstep_move_cardinality_3_worksteps() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        for _ in 0..3 {
            let create_workstep_params = json!({
                "name": format!("{} workstep", Name().fake::<String>()),
            });

            let _ = _create_workstep(
                &baseline,
                &create_workflow_body.id,
                create_workstep_params,
                201,
            )
            .await;
        }

        let fetch_worksteps_res = baseline
            .fetch_worksteps(&create_workflow_body.id)
            .await
            .expect("fetch worksteps response");
        assert_eq!(fetch_worksteps_res.status(), 200);

        let fetch_worksteps_body = fetch_worksteps_res
            .json::<Vec<Workstep>>()
            .await
            .expect("fetch worksteps body");

        for workstep_idx in 0..3 {
            let current_workstep = &fetch_worksteps_body[workstep_idx];
            let original_cardinality = current_workstep.cardinality;

            for cardinality in 1..4 {
                let update_workstep_params = json!({
                    "name": &current_workstep.name,
                    "cardinality": cardinality,
                    "status": "draft",
                });

                let update_workstep_res = baseline
                    .update_workstep(
                        &create_workflow_body.id,
                        &current_workstep.id,
                        Some(update_workstep_params),
                    )
                    .await
                    .expect("update workstep response");
                assert_eq!(
                    update_workstep_res.status(),
                    204,
                    "update workstep response body: {:?}",
                    update_workstep_res.json::<Value>().await.unwrap()
                );

                let updated_workstep_res = baseline
                    .get_workstep(&create_workflow_body.id, &current_workstep.id)
                    .await
                    .expect("fetch updated workstep response");
                assert_eq!(updated_workstep_res.status(), 200);

                let updated_workstep_body = updated_workstep_res
                    .json::<Workstep>()
                    .await
                    .expect("updated workstep body");
                assert_eq!(updated_workstep_body.cardinality, cardinality);

                // reset the cardinality back to its original after each shift
                let revert_workstep_cardinality_params = json!({
                    "name": &current_workstep.name,
                    "cardinality": original_cardinality,
                    "status": "draft",
                });

                let revert_workstep_cardinality_res = baseline
                    .update_workstep(
                        &create_workflow_body.id,
                        &current_workstep.id,
                        Some(revert_workstep_cardinality_params),
                    )
                    .await
                    .expect("revert workstep cardinality response");
                assert_eq!(
                    revert_workstep_cardinality_res.status(),
                    204,
                    "revert workstep cardinality response body: {:?}",
                    update_workstep_res.json::<Value>().await.unwrap()
                );

                let get_reverted_cardinality_workstep_res = baseline
                    .get_workstep(&create_workflow_body.id, &current_workstep.id)
                    .await
                    .expect("get reverted cardinality workstep response");
                assert_eq!(get_reverted_cardinality_workstep_res.status(), 200);

                let get_reverted_cardinality_workstep_res = get_reverted_cardinality_workstep_res
                    .json::<Workstep>()
                    .await
                    .expect("get reverted cardinality workstep body");
                assert_eq!(
                    get_reverted_cardinality_workstep_res.cardinality,
                    original_cardinality
                );
            }
        }
    }

    #[tokio::test]
    async fn update_workstep_move_cardinality_12_worksteps() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        for _ in 0..12 {
            let create_workstep_params = json!({
                "name": format!("{} workstep", Name().fake::<String>()),
            });

            let _ = _create_workstep(
                &baseline,
                &create_workflow_body.id,
                create_workstep_params,
                201,
            )
            .await;
        }

        let fetch_worksteps_res = baseline
            .fetch_worksteps(&create_workflow_body.id)
            .await
            .expect("fetch worksteps response");
        assert_eq!(fetch_worksteps_res.status(), 200);

        let fetch_worksteps_body = fetch_worksteps_res
            .json::<Vec<Workstep>>()
            .await
            .expect("fetch worksteps body");

        for workstep_idx in 0..12 {
            let current_workstep = &fetch_worksteps_body[workstep_idx];
            let original_cardinality = current_workstep.cardinality;

            for cardinality in 1..13 {
                let update_workstep_params = json!({
                    "name": &current_workstep.name,
                    "cardinality": cardinality,
                    "status": "draft",
                });

                let update_workstep_res = baseline
                    .update_workstep(
                        &create_workflow_body.id,
                        &current_workstep.id,
                        Some(update_workstep_params),
                    )
                    .await
                    .expect("update workstep response");
                assert_eq!(
                    update_workstep_res.status(),
                    204,
                    "update workstep response body: {:?}",
                    update_workstep_res.json::<Value>().await.unwrap()
                );

                let updated_workstep_res = baseline
                    .get_workstep(&create_workflow_body.id, &current_workstep.id)
                    .await
                    .expect("fetch updated workstep response");
                assert_eq!(updated_workstep_res.status(), 200);

                let updated_workstep_body = updated_workstep_res
                    .json::<Workstep>()
                    .await
                    .expect("updated workstep body");
                assert_eq!(updated_workstep_body.cardinality, cardinality);

                // reset the cardinality back to its original after each shift
                let revert_workstep_cardinality_params = json!({
                    "name": &current_workstep.name,
                    "cardinality": original_cardinality,
                    "status": "draft",
                });

                let revert_workstep_cardinality_res = baseline
                    .update_workstep(
                        &create_workflow_body.id,
                        &current_workstep.id,
                        Some(revert_workstep_cardinality_params),
                    )
                    .await
                    .expect("revert workstep cardinality response");
                assert_eq!(
                    revert_workstep_cardinality_res.status(),
                    204,
                    "revert workstep cardinality response body: {:?}",
                    update_workstep_res.json::<Value>().await.unwrap()
                );

                let get_reverted_cardinality_workstep_res = baseline
                    .get_workstep(&create_workflow_body.id, &current_workstep.id)
                    .await
                    .expect("get reverted cardinality workstep response");
                assert_eq!(get_reverted_cardinality_workstep_res.status(), 200);

                let get_reverted_cardinality_workstep_res = get_reverted_cardinality_workstep_res
                    .json::<Workstep>()
                    .await
                    .expect("get reverted cardinality workstep body");
                assert_eq!(
                    get_reverted_cardinality_workstep_res.cardinality,
                    original_cardinality
                );
            }
        }
    }

    #[tokio::test]
    async fn update_workstep_fail_cardinality_out_of_bounds() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1"
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_workstep_body = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let update_workstep_negative_cardinality_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "description": "an updated workstep description",
            "status": "draft",
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
            "cardinality": -1,
        });

        let update_workstep_negative_cardinality_res = baseline
            .update_workstep(
                &create_workflow_body.id,
                &create_workstep_body.id,
                Some(update_workstep_negative_cardinality_params),
            )
            .await
            .expect("update workstep response");
        assert_eq!(
            update_workstep_negative_cardinality_res.status(),
            422,
            "update workstep response body: {:?}",
            update_workstep_negative_cardinality_res
                .json::<Value>()
                .await
                .unwrap()
        );

        let update_workstep_cardinality_positive_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "description": "an updated workstep description",
            "status": "draft",
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
            "cardinality": 100,
        });

        let update_workstep_cardinality_positive_res = baseline
            .update_workstep(
                &create_workflow_body.id,
                &create_workstep_body.id,
                Some(update_workstep_cardinality_positive_params),
            )
            .await
            .expect("update workstep response");
        assert_eq!(
            update_workstep_cardinality_positive_res.status(),
            422,
            "update workstep response body: {:?}",
            update_workstep_cardinality_positive_res
                .json::<Value>()
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn delete_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_res = baseline
            .create_workstep(
                &create_workflow_body.id,
                Some(json!({
                    "name": format!("{} workflow", Name().fake::<String>())
                })),
            )
            .await
            .expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);

        let create_workstep_body = create_workstep_res
            .json::<Workstep>()
            .await
            .expect("create workstep body");

        let delete_workstep_res = baseline
            .delete_workstep(&create_workflow_body.id, &create_workstep_body.id)
            .await
            .expect("delete workstep response");
        assert_eq!(delete_workstep_res.status(), 204);
    }

    #[tokio::test]
    async fn delete_workstep_updates_worksteps_count() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_res = baseline
            .create_workstep(
                &create_workflow_body.id,
                Some(json!({
                    "name": format!("{} workflow", Name().fake::<String>())
                })),
            )
            .await
            .expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);

        let create_workstep_body = create_workstep_res
            .json::<Workstep>()
            .await
            .expect("create workstep body");

        let delete_workstep_res = baseline
            .delete_workstep(&create_workflow_body.id, &create_workstep_body.id)
            .await
            .expect("delete workstep response");
        assert_eq!(delete_workstep_res.status(), 204);

        let get_workflow_res = baseline
            .get_workflow(&create_workflow_body.id)
            .await
            .expect("get workstep response");
        assert_eq!(get_workflow_res.status(), 200);

        let get_workstep_body = get_workflow_res
            .json::<Workflow>()
            .await
            .expect("get workstep body");

        assert_eq!(get_workstep_body.worksteps_count, None);
    }

    #[tokio::test]
    async fn delete_workstep_updates_cardinality() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_first_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_first_workstep_body = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_first_workstep_params,
            201,
        )
        .await;

        let create_second_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_second_workstep_body = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_second_workstep_params,
            201,
        )
        .await;

        let delete_workstep_res = baseline
            .delete_workstep(&create_workflow_body.id, &create_first_workstep_body.id)
            .await
            .expect("delete workstep response");
        assert_eq!(delete_workstep_res.status(), 204);

        let get_workstep_res = baseline
            .get_workstep(&create_workflow_body.id, &create_second_workstep_body.id)
            .await
            .expect("get workstep response");
        assert_eq!(get_workstep_res.status(), 200);

        let get_workstep_body = get_workstep_res
            .json::<Workstep>()
            .await
            .expect("get workstep body");

        assert_eq!(get_workstep_body.cardinality, 1);
    }

    #[tokio::test]
    async fn create_workstep_fail_on_deployed() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
        }
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            }
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            400,
        )
        .await;
    }

    #[tokio::test]
    async fn execute_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

        let create_workflow_instance_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "workflow_id": &create_workflow_body.id,
        });

        let create_workflow_instance_body =
            _create_workflow(&baseline, create_workflow_instance_params, 201).await;

        let fetch_workflow_instance_worksteps_res = baseline
            .fetch_worksteps(&create_workflow_instance_body.id)
            .await
            .expect("fetch workflow instance worksteps response");
        assert_eq!(fetch_workflow_instance_worksteps_res.status(), 200);

        let fetch_workflow_instance_worksteps_body = fetch_workflow_instance_worksteps_res
            .json::<Vec<WorkstepInstance>>()
            .await
            .expect("fetch workflow instance worksteps body");

        let execute_workstep_params = json!({
            "witness": {
                "X": "3",
                "Y": "35"
            },
        });

        let execute_workstep_res = baseline
            .execute_workstep(
                &create_workflow_instance_body.id,
                &fetch_workflow_instance_worksteps_body[0].id,
                Some(execute_workstep_params),
            )
            .await
            .expect("execute workstep response");
        assert_eq!(
            execute_workstep_res.status(),
            201,
            "execute workstep response {:?}",
            execute_workstep_res.json::<Value>().await.unwrap()
        );
    }

    #[tokio::test]
    async fn execute_workstep_fail_without_valid_witness() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
        });

        let _ = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

        let create_workflow_instance_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "workflow_id": &create_workflow_body.id,
        });

        let create_workflow_instance_body =
            _create_workflow(&baseline, create_workflow_instance_params, 201).await;

        let fetch_workflow_instance_worksteps_res = baseline
            .fetch_worksteps(&create_workflow_instance_body.id)
            .await
            .expect("fetch workflow instance worksteps response");
        assert_eq!(fetch_workflow_instance_worksteps_res.status(), 200);

        let fetch_workflow_instance_worksteps_body = fetch_workflow_instance_worksteps_res
            .json::<Vec<WorkstepInstance>>()
            .await
            .expect("fetch workflow instance worksteps body");

        let execute_workstep_params = json!({
            "witness": {
                "X": "10",
                "Y": "35"
            },
        });

        let execute_workstep_res = baseline
            .execute_workstep(
                &create_workflow_instance_body.id,
                &fetch_workflow_instance_worksteps_body[0].id,
                Some(execute_workstep_params),
            )
            .await
            .expect("execute workstep response");
        assert_eq!(
            execute_workstep_res.status(),
            400,
            "execute workstep response {:?}",
            execute_workstep_res.json::<Value>().await.unwrap()
        );
    }

    #[tokio::test]
    async fn execute_workstep_fail_on_draft() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
            "version": "1",
        });

        let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": true,
            "metadata": {
                "prover": {
                    "identifier": "cubic",
                    "name": "cubic groth16",
                    "provider": "gnark",
                    "proving_scheme": "groth16",
                    "curve": "BN254",
                },
            },
        });

        let create_workstep_body = _create_workstep(
            &baseline,
            &create_workflow_body.id,
            create_workstep_params,
            201,
        )
        .await;

        let execute_workstep_res = baseline
            .execute_workstep(&create_workflow_body.id, &create_workstep_body.id, None)
            .await
            .expect("execute workstep response");
        assert_eq!(
            execute_workstep_res.status(),
            400,
            "execute workstep response {:?}",
            execute_workstep_res.json::<Value>().await.unwrap()
        );
    }
}
