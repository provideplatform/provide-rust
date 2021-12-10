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

    async fn create_object(&self, params: Params) -> Response;

    async fn update_object(&self, object_id: &str, params: Params) -> Response;

    async fn update_config(&self, params: Params) -> Response;

    async fn create_business_object(&self, params: Params) -> Response;

    async fn update_business_object(&self, business_object_id: &str, params: Params) -> Response;

    async fn get_workflows(&self, params: Params) -> Response;

    async fn get_workflow(&self, workflow_id: &str) -> Response;

    async fn create_workflow(&self, params: Params) -> Response;

    async fn update_workflow(&self, workflow_id: &str, params: Params) -> Response;

    async fn delete_workflow(&self, workflow_id: &str) -> Response;

    async fn deploy_workflow(&self, workflow_id: &str) -> Response;

    async fn get_workgroups(&self) -> Response;

    async fn get_workgroup(&self, workgroup_id: &str) -> Response;

    async fn create_workgroup(&self, params: Params) -> Response;

    async fn get_mappings(&self) -> Response;
    
    // async fn get_mapping(&self) -> Response;

    async fn create_mapping(&self, params: Params) -> Response;

    async fn update_mapping(&self, mapping_id: &str, params: Params) -> Response;

    async fn delete_mapping(&self, mapping_id: &str) -> Response;

    async fn fetch_worksteps(&self, workflow_id: &str) -> Response;

    async fn get_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response;

    async fn create_workstep(&self, workflow_id: &str, params: Params) -> Response;

    async fn update_workstep(&self, workflow_id: &str, workstep_id: &str, params: Params) -> Response;

    async fn delete_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response;
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

    async fn create_object(&self, params: Params) -> Response {
        return self.post("objects", params, None).await;
    }

    async fn update_object(&self, object_id: &str, params: Params) -> Response {
        let uri = format!("objects/{}", object_id);
        return self.put(&uri, params, None).await;
    }

    async fn update_config(&self, params: Params) -> Response {
        return self.put("config", params, None).await;
    }

    async fn create_business_object(&self, params: Params) -> Response {
        return self.post("business_objects", params, None).await;
    }

    async fn update_business_object(&self, business_object_id: &str, params: Params) -> Response {
        let uri = format!("business_objects/{}", business_object_id);
        return self.put(&uri, params, None).await;
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

    async fn delete_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}", workflow_id);
        return self.delete(&uri, None, None).await
    }

    async fn deploy_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}/deploy", workflow_id);
        return self.post(&uri, Some(json!({})), None).await
    }

    async fn get_workgroups(&self) -> Response {
        return self.get("workgroups", None, None).await;
    }

    async fn create_workgroup(&self, params: Params) -> Response {
        return self.post("workgroups", params, None).await;
    }

    async fn get_workgroup(&self, workgroup_id: &str) -> Response {
        let uri = format!("workgroups/{}", workgroup_id);
        return self.get(&uri, None, None).await;
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
    async fn create_workflow() {
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

        // workflow needs a workstep to deploy
        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()), "require_finality": true }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);

        let _ = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()), "require_finality": true }))).await.expect("create workstep response");

        let deploy_workflow_res = baseline.deploy_workflow(&create_workflow_body.id).await.expect("deploy workflow response");
        assert_eq!(deploy_workflow_res.status(), 202, "deploy workstep response body: {:?}", deploy_workflow_res.json::<Value>().await.unwrap());

        // check that workflow status updates to deployed
        let mut interval = time::interval(Duration::from_millis(500));

        let mut deployed_worksteps_status = false;

        // TODO: 2 minute timeout
        // assert that the workstep status
        while deployed_worksteps_status != true {
            let fetch_worksteps_res = baseline.fetch_worksteps(&create_workflow_body.id).await.expect("fetch worksteps response");
            let fetch_worksteps_body = fetch_worksteps_res.json::<Vec<Workstep>>().await.expect("fetch worksteps body");

            let mut count = 0;
            for idx in 0..fetch_worksteps_body.len() - 1 {
                let workstep = &fetch_worksteps_body[idx];
                if workstep.status == "deployed" {
                    count += 1;
                }

                // test cardinality also
                assert_eq!(workstep.cardinality, idx)
            }

            if count == fetch_worksteps_body.len() {
                deployed_worksteps_status = true
            } else {
                interval.tick().await;
            }
        }
        assert!(deployed_worksteps_status);

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

        let create_workflow_params = json!({
            "workgroup_id": &app_id,
            "name": format!("{} workflow", Name().fake::<String>()),
        });

        let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
        assert_eq!(create_workflow_res.status(), 201, "create workflow response body: {:?}", create_workflow_res.json::<Value>().await.unwrap());

        let create_workflow_body = create_workflow_res.json::<Workflow>().await.expect("create workflow body");

        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);
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
    }
    
    #[tokio::test]
    async fn update_workstep_cardinality() {
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

        // create worksteps
        let create_first_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create workstep response");
        assert_eq!(create_first_workstep_res.status(), 201);
        let create_first_workstep_body = create_first_workstep_res.json::<Workstep>().await.expect("create first workstep body");

        let create_second_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workstep", Name().fake::<String>()) }))).await.expect("create workstep response");
        assert_eq!(create_second_workstep_res.status(), 201);
        let create_second_workstep_body = create_second_workstep_res.json::<Workstep>().await.expect("create second workstep body");

        let update_second_workstep_params = json!({
            "name": &create_second_workstep_body.name,
            "status": &create_second_workstep_body.status,
            "cardinality": &create_second_workstep_body.cardinality,
        });
        
        let update_second_workstep_res = baseline.update_workstep(&create_workflow_body.id, &create_second_workstep_body.id, Some(update_second_workstep_params)).await.expect("update second workstep response");
        assert_eq!(update_second_workstep_res.status(), 204);

        let update_first_workstep_params = json!({
            "name": &create_first_workstep_body.name,
            "status": &create_first_workstep_body.status,
            "cardinality": &create_first_workstep_body.cardinality,
        });

        let update_first_workstep_res = baseline.update_workstep(&create_workflow_body.id, &create_first_workstep_body.id, Some(update_first_workstep_params)).await.expect("update first workstep response");
        assert_eq!(update_first_workstep_res.status(), 204);

        // TODO: fetch all worksteps after changing the cardinality in each and check they are ordered correctly
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

        // create worksteps
        let create_workstep_res = baseline.create_workstep(&create_workflow_body.id, Some(json!({ "name": format!("{} workflow", Name().fake::<String>()) }))).await.expect("create workstep response");
        assert_eq!(create_workstep_res.status(), 201);

        let create_workstep_body = create_workstep_res.json::<Workstep>().await.expect("create workstep body");

        let delete_workstep_res = baseline.delete_workstep(&create_workflow_body.id, &create_workstep_body.id).await.expect("delete workstep response");
        assert_eq!(delete_workstep_res.status(), 204);
    }

    // #[tokio::test]
    // async fn create_workflow_instance() {
    //     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    //     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    //     let org_access_token_json = config_vals["org_access_token"].to_string();
    //     let org_access_token = serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    //     let baseline: ApiClient = Baseline::factory(&org_access_token);

    //     let create_workflow_params = json!({
    //        "participants": [],
    //        "version": "",
    //        "worksteps": [],
    //     });

    //     let create_workflow_res = baseline.create_workflow(Some(create_workflow_params)).await.expect("create workflow response");
    //     assert_eq!(create_workflow_res.status(), 201);

    //     // let create_workflow_body = create_workflow_res.json::<Value>().await.expect("create workflow body");

    //     let create_workflow_instance_params = json!({
    //         "participants": [],
    //         "version": "",
    //         "worksteps": [],
    //         "workflow_id": "",
    //         "shield": "",
    //         "status": "",
    //     });

    //     let create_workflow_instance_res = baseline.create_workflow(Some(create_workflow_instance_params)).await.expect("create workflow instance response");
    //     assert_eq!(create_workflow_instance_res.status(), 201);
    // }


    

    #[tokio::test]
    async fn get_workgroups() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let get_workgroups_res = baseline
            .get_workgroups()
            .await
            .expect("get workgroups response");
        assert_eq!(get_workgroups_res.status(), 200);
    }

    #[tokio::test]
    async fn create_object() {
        let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
        let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

        let org_access_token_json = config_vals["org_access_token"].to_string();
        let org_access_token = serde_json::from_str::<String>(&org_access_token_json)
            .expect("organzation access token");

        let baseline: ApiClient = Baseline::factory(&org_access_token);

        let workgroup_id_json = config_vals["app_id"].to_string();
        let workgroup_id =
            serde_json::from_str::<String>(&workgroup_id_json).expect("workgroup id");
        println!("APP ID {}", &workgroup_id);

        let organization_id_json = config_vals["org_id"].to_string();
        let organization_id =
            serde_json::from_str::<String>(&organization_id_json).expect("organization id");
        println!("ORG ID {}", &organization_id);

        let create_object_params = json!({
            // "workgroup_id": &workgroup_id,
            // "organization_id": &organization_id,_id,
            "id": "asdfg",
            // "baseline_id": null,
            // "identifier": "abcd", // USE FAKER lorem::Word()
            "payload": {
                "hello": "world",
            },
            "type": "general_consistency",
        });

        // select workgroup
        // select organization
        // type
        // id
        // baseline_id
        // payload

        let create_object_res = baseline
            .create_object(Some(create_object_params))
            .await
            .expect("create object response");
        assert_eq!(create_object_res.status(), 202);
    }

    // #[tokio::test]
    // async fn create_object_baseline_id_infinte() {
    // }

    // TODO: test the response here with passing valid vs nonexistent uuid in query string
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
}

// create workgroup helper
// check issue kyle had
// add examples dir with examples for each feature (standard, WASM, pure-rust?)

// TODO: when status code assertions fail, the res code AND res body err message should be logged
// response body types as well as request body type ofc

// 31 methods total


// [GIN-debug] GET    /status                   --> main.statusHandler (4 handlers)
// [GIN-debug] POST   /api/v1/credentials       --> github.com/provideplatform/baseline/baseline.issueVerifiableCredentialHandler (4 handlers)
// [GIN-debug] POST   /api/v1/pub/invite        --> github.com/provideplatform/baseline/baseline.createPublicWorkgroupInviteHandler (4 handlers)
// [GIN-debug] GET    /api/v1/bpi_accounts      --> github.com/provideplatform/baseline/baseline.listBPIAccountsHandler (7 handlers)
// [GIN-debug] GET    /api/v1/bpi_accounts/:id  --> github.com/provideplatform/baseline/baseline.bpiAccountDetailsHandler (7 handlers)
// [GIN-debug] POST   /api/v1/bpi_accounts      --> github.com/provideplatform/baseline/baseline.createBPIAccountHandler (7 handlers)
// [GIN-debug] POST   /api/v1/protocol_messages --> github.com/provideplatform/baseline/baseline.createProtocolMessageHandler (7 handlers)
// [GIN-debug] GET    /api/v1/subjects          --> github.com/provideplatform/baseline/baseline.listSubjectsHandler (7 handlers)
// [GIN-debug] GET    /api/v1/subjects/:id      --> github.com/provideplatform/baseline/baseline.subjectDetailsHandler (7 handlers)
// [GIN-debug] POST   /api/v1/subjects          --> github.com/provideplatform/baseline/baseline.createSubjectHandler (7 handlers)
// [GIN-debug] PUT    /api/v1/subjects/:id      --> github.com/provideplatform/baseline/baseline.updateSubjectHandler (7 handlers)
// [GIN-debug] GET    /api/v1/subjects/:id/accounts --> github.com/provideplatform/baseline/baseline.listSubjectAccountsHandler (7 handlers)
// [GIN-debug] GET    /api/v1/subjects/:id/accounts/:accountId --> github.com/provideplatform/baseline/baseline.subjectAccountDetailsHandler (7 handlers)
// [GIN-debug] POST   /api/v1/subjects/:id/accounts --> github.com/provideplatform/baseline/baseline.createSubjectAccountsHandler (7 handlers)
// [GIN-debug] PUT    /api/v1/subjects/:id/accounts/:accountId --> github.com/provideplatform/baseline/baseline.updateSubjectAccountsHandler (7 handlers)
// [GIN-debug] GET    /api/v1/mappings          --> github.com/provideplatform/baseline/baseline.listMappingsHandler (7 handlers)
// [GIN-debug] POST   /api/v1/mappings          --> github.com/provideplatform/baseline/baseline.createMappingHandler (7 handlers)
// [GIN-debug] PUT    /api/v1/mappings/:id      --> github.com/provideplatform/baseline/baseline.updateMappingHandler (7 handlers)
// [GIN-debug] DELETE /api/v1/mappings/:id      --> github.com/provideplatform/baseline/baseline.deleteMappingHandler (7 handlers)
// [GIN-debug] POST   /api/v1/objects           --> github.com/provideplatform/baseline/baseline.createObjectHandler (7 handlers)
// [GIN-debug] PUT    /api/v1/objects/:id       --> github.com/provideplatform/baseline/baseline.updateObjectHandler (7 handlers)
// [GIN-debug] PUT    /api/v1/config            --> github.com/provideplatform/baseline/baseline.configurationHandler (7 handlers)
// [GIN-debug] POST   /api/v1/business_objects  --> github.com/provideplatform/baseline/baseline.createObjectHandler (7 handlers)
// [GIN-debug] PUT    /api/v1/business_objects/:id --> github.com/provideplatform/baseline/baseline.updateObjectHandler (7 handlers)
// [GIN-debug] GET    /api/v1/workflows         --> github.com/provideplatform/baseline/baseline.listWorkflowsHandler (7 handlers)
// [GIN-debug] GET    /api/v1/workflows/:id     --> github.com/provideplatform/baseline/baseline.workflowDetailsHandler (7 handlers)
// [GIN-debug] POST   /api/v1/workflows         --> github.com/provideplatform/baseline/baseline.createWorkflowHandler (7 handlers)
// [GIN-debug] PUT    /api/v1/workflows/:id     --> github.com/provideplatform/baseline/baseline.updateWorkflowHandler (7 handlers)
// [GIN-debug] POST   /api/v1/workflows/:id/deploy --> github.com/provideplatform/baseline/baseline.deployWorkflowHandler (7 handlers)
// [GIN-debug] DELETE /api/v1/workflows/:id     --> github.com/provideplatform/baseline/baseline.deleteWorkflowHandler (7 handlers)
// [GIN-debug] GET    /api/v1/workgroups        --> github.com/provideplatform/baseline/baseline.listWorkgroupsHandler (7 handlers)
// time="2021-12-09T20:31:26Z" level=debug msg="listening on 0.0.0.0:8080"
// [GIN-debug] GET    /api/v1/workgroups/:id    --> github.com/provideplatform/baseline/baseline.workgroupDetailsHandler (7 handlers)
// [GIN-debug] POST   /api/v1/workgroups        --> github.com/provideplatform/baseline/baseline.createWorkgroupHandler (7 handlers)
// [GIN-debug] GET    /api/v1/worksteps         --> github.com/provideplatform/baseline/baseline.listWorkstepsHandler (7 handlers)
// [GIN-debug] GET    /api/v1/workflows/:id/worksteps --> github.com/provideplatform/baseline/baseline.listWorkstepsHandler (7 handlers)
// [GIN-debug] GET    /api/v1/workflows/:id/worksteps/:workstepId --> github.com/provideplatform/baseline/baseline.workstepDetailsHandler (7 handlers)
// [GIN-debug] POST   /api/v1/workflows/:id/worksteps --> github.com/provideplatform/baseline/baseline.createWorkstepHandler (7 handlers)
// [GIN-debug] PUT    /api/v1/workflows/:id/worksteps/:workstepId --> github.com/provideplatform/baseline/baseline.updateWorkstepHandler (7 handlers)
// [GIN-debug] DELETE /api/v1/workflows/:id/worksteps/:workstepId --> github.com/provideplatform/baseline/baseline.deleteWorkstepHandler (7 handlers)
// [GIN-debug] POST   /api/v1/workflows/:id/worksteps/:workstepId/execute --> github.com/provideplatform/baseline/baseline.executeWorkstepHandler (7 handlers)
// [GIN-debug] POST   /api/v1/stats             --> github.com/provideplatform/baseline/stats.statsLogHandler (7 handlers)