use async_trait::async_trait;
use serde_json::json;
use crate::api::client::{ApiClient, Params, Response};
pub use crate::models::baseline::*;

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

    async fn update_workstep(&self, workflow_id: &str, workstep_id: &str, params: Params) -> Response;

    async fn delete_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response;

    async fn execute_workstep(&self, workflow_id: &str, workstep_id: &str, params: Params) -> Response;
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
        return self.delete(&uri, None, None).await
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
        return self.put(&uri, params, None).await
    }
    
    async fn deploy_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}/deploy", workflow_id);
        // return self.post(&uri, Some(json!({ "": "" })), None).await
        return self.post(&uri, None, None).await
    }
    
    async fn delete_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}", workflow_id);
        return self.delete(&uri, None, None).await
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

    async fn update_workstep(&self, workflow_id: &str, workstep_id: &str, params: Params) -> Response {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.put(&uri, params, None).await;
    }

    async fn delete_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.delete(&uri, None, None).await;
    }

    async fn execute_workstep(&self, workflow_id: &str, workstep_id: &str, params: Params) -> Response {
        let uri = format!("workflows/{}/worksteps/{}/execute", workflow_id, workstep_id);
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

    async fn generate_application(ident: &ApiClient, user_id: &str) -> Application {
        let application_data = json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": user_id,
            "name": format!("{} application", Name().fake::<String>()),
            "description": "Some application description",
            "type": "baseline",
            "hidden": false
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
            "name": format!("{} organization", Name().fake::<String>()).chars().filter(|c| !c.is_whitespace()).collect::<String>(),
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
        // let mut sleep_count = 0;

        // while sleep_count < 20 {
        //     Command::new("sh")
        //         .arg("-c")
        //         .arg("docker network ls")
        //         .output()
        //         .unwrap();

        //     sleep_count += 1;
        //     time::sleep(time::Duration::from_secs(1)).await;
        // };

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
            generate_application(&ident, &authentication_res_body.user.id).await;
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
            .associate_application_organization(
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
        assert_eq!(create_account_res.status(), 201, "create account response body: {:?}", create_account_res.json::<Value>().await.unwrap());
        let create_account_body = create_account_res
            .json::<Account>()
            .await
            .expect("create account body");
        let create_contract_params = json!({
            "address": "0x",
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
            .expect("create key resposne");
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
            std::fs::File::create(".test-config.tmp.json").expect("baseline json config"),
            &json_config_params,
        )
        .expect("write json");

        // yaml config file
        let config_file_contents = format!(
            "access-token: {}\nrefresh-token: {}\n{}:\n  api-token: {}\n",
            &user_access_token, &user_refresh_token, &create_application_body.id, &app_access_token
        );
        let cwd = match std::env::current_dir() {
            Ok(path) => path
                .into_os_string()
                .into_string()
                .expect("current working directory"),
            Err(v) => panic!("{:?}", v),
        };
        let config_file_name = format!("{}/.local-baseline-test-config.tmp.yaml", cwd);
        let mut config_file = std::fs::File::create(&config_file_name).expect("config file name");
        write!(config_file, "{}", config_file_contents).expect("config contents");

        // start command & environment
        let run_env = format!("LOG_LEVEL=TRACE IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http NCHAIN_API_HOST=localhost:8084 NCHAIN_API_SCHEME=http VAULT_API_HOST=localhost:8082 VAULT_API_SCHEME=http PROVIDE_ORGANIZATION_REFRESH_TOKEN={}", &org_refresh_token);

        let mut run_cmd = String::from("prvd baseline stack start");
        run_cmd += &format!(" --api-endpoint={}", "http://localhost:8086");
        run_cmd += &format!(" --config={}", &config_file_name);
        run_cmd += &format!(
            " --ident-host={}",
            std::env::var("IDENT_API_HOST").unwrap_or(String::from("localhost:8081"))
        ); // TODO: use env
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
        run_cmd += &format!(" --postgres-hostname={}-postgres", &create_organization_body.name);
        run_cmd += &format!(" --postgres-port={}", "5433");

        let localhost_regex = regex::Regex::new(r"localhost").expect("localhost regex expression");
        run_cmd = localhost_regex
            .replace_all(&run_cmd, "host.docker.internal")
            .to_string();
        let baseline_cmd = format!("{} {}", run_env, run_cmd);

        Command::new("sh")
            .arg("-c")
            .arg(&baseline_cmd)
            .spawn()
            .expect("baseline tests init process"); // attach to some sort of log level?

        let mut baseline_status_client = ApiClient::new("", "", "", "");
        baseline_status_client.set_base_url(&format!(
            "{}://{}",
            std::env::var("BASELINE_API_SCHEME").expect("baseline api scheme"),
            std::env::var("BASELINE_API_HOST").expect("baseline api host")
        ));

        let mut baseline_container_status = String::from("");

        while baseline_container_status == "" {
            baseline_container_status = match baseline_status_client.get("status", None, None).await
            {
                Ok(res) => res.status().to_string(),
                Err(_) => String::from(""),
            };

            interval.tick().await;
        }

        assert_eq!(baseline_container_status, "204 No Content"); // these logs probably shouldn't show unless baseline suite is specified
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
        assert_eq!(create_mapping_res.status(), 201);
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
        assert_eq!(create_mapping_res.status(), 201);

        let create_mapping_body = create_mapping_res.json::<Mapping>().await.expect("create mapping body");

        let update_mapping_params = json!({
            "description": "An updated mapping description",
            "models": [
                {
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
                },
                {
                    "type": "SalesOrder",
                    "fields": [
                        {
                            "name": "id",
                            "is_primary_key": false,
                        },
                        {
                            "name": "identifier",
                            "is_primary_key": true,
                        },
                    ],
                    "primary_key": "id",
                },
            ],
        });

        let update_mapping_res = baseline
            .update_mapping(&create_mapping_body.id, Some(update_mapping_params))
            .await
            .expect("update mapping response");
        assert_eq!(update_mapping_res.status(), 204);
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
        assert_eq!(create_mapping_res.status(), 201);

        let create_mapping_body = create_mapping_res.json::<Mapping>().await.expect("create mapping body");

        let delete_mapping_res = baseline.delete_mapping(&create_mapping_body.id).await.expect("delete mapping response");
        assert_eq!(delete_mapping_res.status(), 204);
    }

    // #[tokio::test]
    // async fn update_config() {}

    /*
        WORKFLOWS
            get workflows
            get workflow
                workflow workstep_count is accurate
            create workflow
            update workflow
            deploy workflow
            workflow status changes to deployed
                fails if workflow doesn't have worksteps
                fails if the last workstep is not require finality
                all of the workstep statuses on a deployed workflow change to deployed
                can update deployed workflow status to deprecated
            delete workflow
                cannot delete a deployed workflow ?
            create workflow instance
    */

    #[tokio::test]
    async fn get_workflows() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

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
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");
        
        // assertion that the worksteps count is accurate
        baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create workstep response");
        baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create workstep response");
        
        let get_workflow_res = baseline.get_workflow(&create_workflow_body.id).await.expect("get workflow response");
        assert_eq!(get_workflow_res.status(), 200);

        let get_workflow_body = get_workflow_res.json::<Workflow>().await.expect("get workflow body");
        assert_eq!(get_workflow_body.worksteps_count.unwrap(), 2);
    }

    #[tokio::test]
    async fn create_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        // test all possible params
        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());
    }

    #[tokio::test]
    async fn create_workflow_instance() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        // assertion that workflow instances cannot be created from undeployed workflows
        let create_workflow_instance_fail_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "workflow_id": &create_workflow_body.id,
        });

        let create_workflow_instance_fail_response = baseline.create_workflow(Some(create_workflow_instance_fail_params)).await.expect("create workflow instance response");
        assert_eq!(create_workflow_instance_fail_response.status(), 422, "Create workflow instance fail response {:?}", create_workflow_instance_fail_response.json::<Value>().await.unwrap());

        baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()), "require_finality": true }))).await.expect("create workstep response");

        let deploy_workflow_res = baseline.deploy_workflow(&create_workflow_body.id).await.expect("deploy workflow response");
        assert_eq!(deploy_workflow_res.status(), 202, "deploy workflow response body: {:?}", deploy_workflow_res.json::<Value>().await.unwrap());

        // do i need to wait for the workflow to be deployed vs pending_deployment?
        let create_workflow_instance_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "workflow_id": &create_workflow_body.id,
        });

        let create_workflow_instance_fail_response = baseline.create_workflow(Some(create_workflow_instance_params)).await.expect("create workflow instance response");
        assert_eq!(create_workflow_instance_fail_response.status(), 201, "Create workflow instance response {:?}", create_workflow_instance_fail_response.json::<Value>().await.unwrap());
    }
    
    #[tokio::test]
    async fn update_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        let update_workflow_params = json!({
            "name": format!("{} workflow", Name().fake::<String>()),
            "status": "draft",
        });

        let update_workflow_res = baseline.update_workflow(&create_workflow_body.id, Some(update_workflow_params)).await.expect("update workflow response");
        assert_eq!(update_workflow_res.status(), 204, "update workflow response body: {:?}", update_workflow_res.json::<Value>().await.unwrap());
    }
    
    #[tokio::test]
    async fn deploy_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        /*
            fails if workflow doesn't have worksteps
        */
        let deploy_workflow_fail_worksteps_res = baseline.deploy_workflow(&create_workflow_body.id).await.expect("deploy workflow fail response");
        assert_eq!(deploy_workflow_fail_worksteps_res.status(), 422, "deploy workflow fail worksteps response {:?}", deploy_workflow_fail_worksteps_res.json::<Value>().await.unwrap());

        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()), "require_finality": true }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);
        
        /*
            fails if the last workstep is not require finality
        */
        let deploy_workflow_fail_finality_res = baseline.deploy_workflow(&create_workflow_body.id).await.expect("deploy workflow response");
        assert_eq!(deploy_workflow_fail_finality_res.status(), 202, "deploy workflow fail finality response body: {:?}", deploy_workflow_fail_finality_res.json::<Value>().await.unwrap());
        
        baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()), "require_finality": true }))).await.expect("create workstep response");

        let deploy_workflow_res = baseline.deploy_workflow(&create_workflow_body.id).await.expect("deploy workflow response");
        assert_eq!(deploy_workflow_res.status(), 202, "deploy workflow response body: {:?}", deploy_workflow_res.json::<Value>().await.unwrap());

        /*
            workstep statuses change to deployed        
        */
        let mut interval = time::interval(Duration::from_millis(500));

        let mut deployed_worksteps_status = false;
        
        while deployed_worksteps_status != true {
            let fetch_worksteps_res = baseline.fetch_worksteps(&create_workflow_body.id).await.expect("fetch worksteps response");
            let fetch_worksteps_body = fetch_worksteps_res.json::<Vec<Workstep>>().await.expect("fetch worksteps body");

            let mut count = 0;
            for idx in 0..fetch_worksteps_body.len() - 1 {
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

        /*
            workflow status changes to deployed
        */
        let mut deployed_workflow_status = String::from("");

        while deployed_workflow_status != "deployed" {
            let looped_deploy_workflow_res = baseline.get_workflow(&create_workflow_body.id).await.expect("looping deploy workflow response");
            let looped_deploy_workflow_body = looped_deploy_workflow_res.json::<Workflow>().await.expect("deploy workflow body");
            deployed_workflow_status = looped_deploy_workflow_body.status;

            if deployed_workflow_status != "deployed" {
                interval.tick().await;
            }
        };
        assert_eq!(deployed_workflow_status, "deployed".to_string()); // is to_string() necessary

        /*
            can update a deployed workflow status to deprecated
        */
        let update_deployed_workflow_deprecated = json!({
            "name": &create_workflow_body.id,
            "status": "deprecated",
        });

        let update_deployed_workflow_deprecated_res = baseline.update_workflow(&create_workflow_body.id, Some(update_deployed_workflow_deprecated)).await.expect("update deployed workflow deprecated response");
        assert_eq!(update_deployed_workflow_deprecated_res.status(), 204);
    }
    
    #[tokio::test]
    async fn delete_workflow() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");
        
        let delete_workflow_res = baseline.delete_workflow(&create_workflow_body.id).await.expect("delete workflow response");
        assert_eq!(delete_workflow_res.status(), 204);

        /*
            cannot delete a deployed workflow
        */


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

    /*
        WORKSTEPS
            fetch worksteps
            get workstep
            create workstep
                cannot create worksteps on deployed workflow (non draft?)
            update workstep
                cannot update worksteps on deployed workflow (non draft?)
                can move cardinality up and down
                cannot move cardinality out of bounds
            delete workstep
                cannot delete workstep on deployed workflow (non draft?)
                deleting workstep changes the workflow workstep_count
                deleting workstep changes the other workstep cardinalities accurately
            create workstep instance
                cannot create workstep instance on draft workflow
            execute workstep
                cannot execute workstep on draft workflow
    */

    #[tokio::test]
    async fn fetch_worksteps() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        let fetch_worksteps_res = baseline.fetch_worksteps(&create_workflow_body.id).await.expect("fetch worksteps response");
        assert_eq!(fetch_worksteps_res.status(), 200);
    }

    #[tokio::test]
    async fn get_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);

        let create_workstep_body = create_workstep_res.json::<Workstep>().await.expect("create workstep body");
        
        let get_workstep_res = baseline.get_workstep(&create_workflow_body.id, &create_workstep_body.id).await.expect("get workstep response");
        assert_eq!(get_workstep_res.status(), 200);
    }
    
    #[tokio::test]
    async fn create_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        // use all the possible params
        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()), "require_finality": true }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);

        let deploy_workflow_res = baseline.deploy_workflow(&create_workflow_body.id).await.expect("deploy workflow response");
        assert_eq!(deploy_workflow_res.status(), 202, "deploy workflow response body: {:?}", deploy_workflow_res.json::<Value>().await.unwrap());

        /*
            cannot create worksteps on deployed workflow (non draft?)
        */
        let create_workstep_fail_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create workstep fail response");
        assert_eq!(create_workstep_fail_res.status(), 400, "create workstep fail response {:?}", create_workstep_fail_res.json::<Value>().await.unwrap());
    }

    #[tokio::test]
    async fn create_workstep_instance() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        // assertion that workflow instances cannot be created from undeployed workflows
        let create_workflow_instance_fail_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
            "workflow_id": &create_workflow_body.id,
        });

        let create_workflow_instance_fail_response = baseline.create_workflow(Some(create_workflow_instance_fail_params)).await.expect("create workflow instance response");
        assert_eq!(create_workflow_instance_fail_response.status(), 422, "Create workflow instance fail response {:?}", create_workflow_instance_fail_response.json::<Value>().await.unwrap());

        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()), "require_finality": true }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);

        let create_workstep_body = create_workstep_res.json::<Workstep>().await.expect("create workstep body");

        let deploy_workflow_res = baseline.deploy_workflow(&create_workflow_body.id).await.expect("deploy workflow response");
        assert_eq!(deploy_workflow_res.status(), 202, "deploy workflow response body: {:?}", deploy_workflow_res.json::<Value>().await.unwrap());

        let create_workstep_instance_params = json!({
            "name": format!("{} workstep instance", Name().fake::<String>()),
            "workflow_id": &create_workflow_body.id,
            "workstep_id": &create_workstep_body.id,
        });

        let create_workstep_instance_res = baseline.create_workstep(&create_workflow_body.id, Some(create_workstep_instance_params)).await.expect("create workstep instance response");
        assert_eq!(create_workstep_instance_res.status(), 201);
    }
    
    #[tokio::test]
    async fn update_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);
        let create_workstep_body = create_workstep_res.json::<Workstep>().await.expect("create workstep body");

        // TODO: test the params you can have / update in a workstep
        let update_workstep_params = json!({
            "description": "an updated workstep description",
            "status": "draft",
            "name": &create_workstep_body.name, 
        });

        let update_workstep_res = baseline.update_workstep(&create_workflow_body.id, &create_workstep_body.id, Some(update_workstep_params)).await.expect("update workstep response");
        assert_eq!(update_workstep_res.status(), 204, "update workstep response body: {:?}", update_workstep_res.json::<Value>().await.unwrap());

        // create worksteps
        let create_first_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create first workstep response");
        assert_eq!(create_first_workstep_res.status(), 201, "{:?}", create_first_workstep_res.json::<Value>().await.unwrap());
        let create_first_workstep_body = create_first_workstep_res.json::<Workstep>().await.expect("create first workstep body");

        let create_second_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create second workstep response");
        assert_eq!(create_second_workstep_res.status(), 201);
        let create_second_workstep_body = create_second_workstep_res.json::<Workstep>().await.expect("create second workstep body");

        /*
            can move cardinality up and down
        */
        let update_second_workstep_down_params = json!({
            "name": &create_second_workstep_body.name,
            "status": &create_second_workstep_body.status,
            "cardinality": 1,
        });
        
        let update_second_workstep_down_res = baseline.update_workstep(&create_workflow_body.id, &create_second_workstep_body.id, Some(update_second_workstep_down_params)).await.expect("update second workstep cardinality response");
        assert_eq!(update_second_workstep_down_res.status(), 204);

        let update_second_workstep_up_params = json!({
            "name": &create_second_workstep_body.name,
            "status": &create_second_workstep_body.status,
            "cardinality": 2,
        });
        
        let update_second_workstep_up_res = baseline.update_workstep(&create_workflow_body.id, &create_second_workstep_body.id, Some(update_second_workstep_up_params)).await.expect("update second workstep cardinality response");
        assert_eq!(update_second_workstep_up_res.status(), 204);

        /*
            cannot move cardinality out of bounds
        */
        let update_second_workstep_fail_cardinality_params = json!({
            "name": &create_second_workstep_body.name,
            "status": &create_second_workstep_body.status,
            "cardinality": 10,
        });
        
        let update_second_workstep_fail_cardinality_res = baseline.update_workstep(&create_workflow_body.id, &create_second_workstep_body.id, Some(update_second_workstep_fail_cardinality_params)).await.expect("update second workstep cardinality response");
        assert_eq!(update_second_workstep_fail_cardinality_res.status(), 422, "update second workstep fail cardinality response {:?}", update_second_workstep_fail_cardinality_res.json::<Value>().await.unwrap());

        let update_second_workstep_fail_cardinality_negative_params = json!({
            "name": &create_second_workstep_body.name,
            "status": &create_second_workstep_body.status,
            "cardinality": -1,
        });
        
        let update_second_workstep_fail_cardinality_negative_res = baseline.update_workstep(&create_workflow_body.id, &create_second_workstep_body.id, Some(update_second_workstep_fail_cardinality_negative_params)).await.expect("update second workstep cardinality response");
        assert_eq!(update_second_workstep_fail_cardinality_negative_res.status(), 422, "update second workstep fail cardinality negative response {:?}", update_second_workstep_fail_cardinality_negative_res.json::<Value>().await.unwrap());
    }

    #[tokio::test]
    async fn delete_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workflow", Name().fake::<String>()) }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);

        let create_workstep_body = create_workstep_res.json::<Workstep>().await.expect("create workstep body");

        let delete_workstep_res = baseline.delete_workstep(&create_workflow_body.id, &create_workstep_body.id).await.expect("delete workstep response");
        assert_eq!(delete_workstep_res.status(), 204);

        /*
            deleting workstep changes the workflow workstep_count
            API IS BROKEN
        */
        let get_workflow_res = baseline.get_workflow(&create_workflow_body.id).await.expect("get workflow response");
        assert_eq!(get_workflow_res.status(), 200);

        let get_workflow_body = get_workflow_res.json::<Workflow>().await.expect("get workflow body");
        assert_eq!(get_workflow_body.worksteps_count.unwrap(), 0); // worksteps_count may not exist when no worksteps

        /*
            deleting workstep changes the other workstep cardinalities accurately
        */
        let create_workstep_first_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workflow", Name().fake::<String>()) }))).await.expect("create workstep response");
        assert_eq!(create_workstep_first_res.status(), 201);
        let create_workstep_first_body = create_workstep_first_res.json::<Workstep>().await.expect("create workstep first body");

        let create_workstep_second_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workflow", Name().fake::<String>()) }))).await.expect("create workstep response");
        assert_eq!(create_workstep_second_res.status(), 201);
        let create_workstep_second_body = create_workstep_second_res.json::<Workstep>().await.expect("create workstep first body");

        let delete_workstep_first_res = baseline.delete_workstep(&create_workflow_body.id, &create_workstep_first_body.id).await.expect("delete workstep first response");
        assert_eq!(delete_workstep_first_res.status(), 204);

        let get_workstep_second_res = baseline.get_workstep(&create_workflow_body.id, &create_workstep_second_body.id).await.expect("get workstep second response");
        assert_eq!(get_workstep_second_res.status(), 200);

        let get_workstep_second_body = get_workstep_second_res.json::<Workstep>().await.expect("get workstep second body");
        assert_eq!(get_workstep_second_body.cardinality, 1);

        /*
            cannot delete workstep on deployed workflow (non draft?)
        */
        let create_workstep_fail_deployed_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workflow", Name().fake::<String>()), "require_finality": true }))).await.expect("create workstep fail deployed response");
        assert_eq!(create_workstep_fail_deployed_res.status(), 201);

        let create_workstep_fail_deployed_body = create_workstep_fail_deployed_res.json::<Workstep>().await.expect("create workstep fail deployed body");

        let deploy_workflow_res = baseline.deploy_workflow(&create_workflow_body.id).await.expect("deploy workflow response");
        assert_eq!(deploy_workflow_res.status(), 202, "deploy workflow response body: {:?}", deploy_workflow_res.json::<Value>().await.unwrap());

        let delete_workstep_fail_deployed_res = baseline.delete_workstep(&create_workflow_body.id, &create_workstep_fail_deployed_body.id).await.expect("delete workstep fail deployed response");
        assert_eq!(delete_workstep_fail_deployed_res.status(), 422, "delete workstep fail deployed res {:?}", delete_workstep_fail_deployed_res.json::<Value>().await.unwrap());
    }

    // #[tokio::test]
    // async fn create_workstep_instance() {}

    #[tokio::test]
    async fn execute_workstep() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

        let app_id_json = config_vals["app_id"].to_string();
        let app_id = serde_json::from_str::<String>(&app_id_json)
                .expect("workgroup id");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workstep", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()), "require_finality": true }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);

        let create_workstep_body = create_workstep_res.json::<Workstep>().await.expect("create workstep body");

        // assertion that you cannot execute a workstep on a workflow with "draft" status
        let execute_workstep_fail_draft_res = baseline.execute_workstep(&create_workflow_body.id, &create_workstep_body.id, None).await.expect("execute workstep fail draft response");
        assert_eq!(execute_workstep_fail_draft_res.status(), 400, "execute workstep fail draft response {:?}", execute_workstep_fail_draft_res.json::<Value>().await.unwrap());

        // assertion that you cannot execute a workstep on a workflow with "pending_deployment" status
        let deploy_workflow_res = baseline.deploy_workflow(&create_workflow_body.id).await.expect("deploy workflow response");
        assert_eq!(deploy_workflow_res.status(), 202, "deploy workflow response body: {:?}", deploy_workflow_res.json::<Value>().await.unwrap());

        let execute_workstep_fail_pending_res = baseline.execute_workstep(&create_workflow_body.id, &create_workstep_body.id, None).await.expect("execute workstep fail pending response");
        assert_eq!(execute_workstep_fail_pending_res.status(), 400, "execute workstep fail pending response {:?}", execute_workstep_fail_pending_res.json::<Value>().await.unwrap());

        // wait for status to change to deployed
        let mut interval = time::interval(Duration::from_millis(500));
        let mut deployed_workflow_status = String::from("");

        while deployed_workflow_status != "deployed" {
            let looped_deploy_workflow_res = baseline.get_workflow(&create_workflow_body.id).await.expect("looping deploy workflow response");
            let looped_deploy_workflow_body = looped_deploy_workflow_res.json::<Workflow>().await.expect("deploy workflow body");
            deployed_workflow_status = looped_deploy_workflow_body.status;

            if deployed_workflow_status != "deployed" {
                interval.tick().await;
            }
        };
        assert_eq!(deployed_workflow_status, "deployed".to_string()); // is to_string() necessary

        let execute_workstep_res = baseline.execute_workstep(&create_workflow_body.id, &create_workstep_body.id, None).await.expect("execute workstep response");
        assert_eq!(execute_workstep_res.status(), 201, "execute workstep response {:?}", execute_workstep_res.json::<Value>().await.unwrap());        
    }
}

// create workgroup helper
// check issue kyle had
// add examples dir with examples for each feature (standard, WASM, pure-rust?)

// TODO: when status code assertions fail, the res code AND res body err message should be logged
// response body types as well as request body type ofc
