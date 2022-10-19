/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use fake::faker::internet::en::{FreeEmail, Password};
use fake::faker::name::en::{FirstName, LastName, Name};
use fake::Fake;
use provide_rust::api::baseline::*;
use provide_rust::api::client::ApiClient;
use provide_rust::api::ident::{AuthenticateResponse, Ident, Organization, Token};
use provide_rust::api::nchain::{
    Account, Contract, NChain, Wallet, KOVAN_TESTNET_NETWORK_ID, POLYGON_MUMBAI_TESTNET_NETWORK_ID,
};
use provide_rust::api::privacy::{
    BLS12_377_CURVE, GNARK_PROVIDER, GROTH16_PROVING_SCHEME, PREIMAGE_HASH_IDENTIFIER,
};
use provide_rust::api::vault::{Vault, VaultContainer, VaultKey};
use provide_rust::models::ident::Application;
use serde_json::{json, Value};
use std::io::Write;
use std::process::Command;
use tokio::time::{self, Duration};

const DEFAULT_DEPLOY_REGISTRY_CONTRACT_TIMEOUT: Duration = Duration::new(5 * 60, 0);
const DEFAULT_DEPLOY_WORKFLOW_TIMEOUT: Duration = Duration::new(3 * 60, 0);

async fn _create_org_registry_contract(
    nchain: &ApiClient,
    network_id: &str,
    wallet_id: &str,
    address: &str,
) {
    // get shuttle registry contract
    let registry_contracts_res = nchain.client.get("https://s3.amazonaws.com/static.provide.services/capabilities/provide-capabilities-manifest.json").send().await.expect("get registry contracts response");
    let registry_contracts = registry_contracts_res
        .json::<Value>()
        .await
        .expect("registry contracts body");
    let compiled_artifact = &registry_contracts["baseline"]["contracts"][1];

    let contract_params = json!({
        "address": address,
        "name": "OrgRegistry",
        "network_id": network_id,
        "params": {
            "argv": [],
            "compiled_artifact": compiled_artifact,
            "wallet_id": wallet_id,
        },
        "type": "organization-registry",
    });

    let create_contract_res = nchain
        .create_contract(Some(contract_params))
        .await
        .expect("create contract res");
    assert_eq!(create_contract_res.status(), 201);
}

async fn _deploy_registry_contract(
    nchain: &ApiClient,
    network_id: &str,
    wallet_id: &str,
) -> String {
    // get shuttle registry contract
    let registry_contracts_res = nchain.client.get("https://s3.amazonaws.com/static.provide.services/capabilities/provide-capabilities-manifest.json").send().await.expect("get registry contracts response");
    let registry_contracts = registry_contracts_res
        .json::<Value>()
        .await
        .expect("registry contracts body");
    let compiled_artifact = &registry_contracts["baseline"]["contracts"][2];

    let contract_params = json!({
        "address": "0x",
        "name": "Shuttle",
        "network_id": network_id,
        "params": {
            "argv": [],
            "compiled_artifact": compiled_artifact,
            "wallet_id": wallet_id,
        },
        "type": "registry",
    });

    let create_contract_res = nchain
        .create_contract(Some(contract_params))
        .await
        .expect("create contract res");
    assert_eq!(create_contract_res.status(), 201);

    let mut registry_contract = create_contract_res
        .json::<Contract>()
        .await
        .expect("create contract body");

    let mut interval = time::interval(Duration::from_millis(500));
    let now = std::time::Instant::now();

    while registry_contract.address == "0x" {
        interval.tick().await;

        if now.elapsed() >= DEFAULT_DEPLOY_REGISTRY_CONTRACT_TIMEOUT {
            panic!("failed to deploy registry contract; deploying registry contract timed out");
        }

        let get_contract_res = nchain
            .get_contract(&registry_contract.id, None)
            .await
            .expect("get contract response");
        assert_eq!(get_contract_res.status(), 200);

        registry_contract = get_contract_res
            .json::<Contract>()
            .await
            .expect("get contract body");
    }

    registry_contract.address
}

async fn _create_workflow(baseline: &ApiClient, params: Value, expected_status: u16) -> Workflow {
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
        let mut interval = time::interval(Duration::from_secs(5));
        let now = std::time::Instant::now();

        let mut deployed_worksteps_status = false;

        while deployed_worksteps_status != true {
            let fetch_worksteps_res = baseline
                .list_worksteps(workflow_id, None)
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

                if now.elapsed() >= DEFAULT_DEPLOY_WORKFLOW_TIMEOUT {
                    panic!("failed to deploy workflow; deploying workflow worksteps timed out");
                }
            }
        }
        assert!(deployed_worksteps_status);

        let mut deployed_workflow_status = false;

        while deployed_workflow_status != true {
            let get_workflow_res = baseline
                .get_workflow(workflow_id, None)
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

                if now.elapsed() >= DEFAULT_DEPLOY_WORKFLOW_TIMEOUT {
                    assert!(
                        false,
                        "failed to deploy workflow; deploying workflow timed out"
                    );
                }
            }
        }
        assert!(deployed_workflow_status);
    }
}

async fn generate_workgroup(baseline: &ApiClient) -> Workgroup {
    let workgroup_params = json!({
        "network_id": KOVAN_TESTNET_NETWORK_ID,
        "name": format!("{} application", Name().fake::<String>()),
        "type": "baseline",
    });

    let create_workgroup_res = baseline
        .create_workgroup(Some(workgroup_params))
        .await
        .expect("generate workgroup response");
    assert_eq!(create_workgroup_res.status(), 201);

    return create_workgroup_res
        .json::<Workgroup>()
        .await
        .expect("create workgroup body");
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

#[ignore]
#[tokio::test]
async fn baseline_setup() {
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
        .authenticate_organization(Some(organization_authorization_params))
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

    let vault: ApiClient = Vault::factory(&org_access_token);

    let create_vault_params = json!({
         "name": "organization vault",
    });

    let create_organization_vault_res = vault
        .create_vault(Some(create_vault_params))
        .await
        .expect("create organization vault res");
    assert_eq!(create_organization_vault_res.status(), 201);

    let create_organization_vault_res = create_organization_vault_res
        .json::<VaultContainer>()
        .await
        .expect("create organization vault body");

    let key_specs = vec!["secp256k1", "RSA-4096", "babyJubJub"];
    let mut org_address = String::default();
    for spec in key_specs {
        let create_key_params = json!({
            "name": format!("{} key", spec),
            "spec": spec,
            "type": "asymmetric",
            "usage": "sign/verify",
        });

        let create_organization_key_res = vault
            .create_key(&create_organization_vault_res.id, Some(create_key_params))
            .await
            .expect("create organization key res");
        assert_eq!(create_organization_key_res.status(), 201);

        if spec == "secp256k1" {
            let create_organization_key_body = create_organization_key_res
                .json::<VaultKey>()
                .await
                .expect("create organization key body");
            org_address = create_organization_key_body.address.unwrap();
        }
    }

    let nchain: ApiClient = NChain::factory(&org_access_token);

    // deploy workgroup contract
    let create_wallet_params = json!({
        "purpose": 44,
    });
    let create_wallet_res = nchain
        .create_wallet(Some(create_wallet_params))
        .await
        .expect("create wallet response");
    assert_eq!(
        create_wallet_res.status(),
        201,
        "create wallet response body: {:?}",
        create_wallet_res.json::<Value>().await.unwrap()
    ); // FAILS HERE RARELY
    let create_wallet_body = create_wallet_res
        .json::<Wallet>()
        .await
        .expect("create account body");

    let mut registry_contract_address =
        std::env::var("BASELINE_REGISTRY_CONTRACT_ADDRESS").unwrap_or(String::from("0x"));

    if registry_contract_address == "0x" {
        registry_contract_address =
            _deploy_registry_contract(&nchain, KOVAN_TESTNET_NETWORK_ID, &create_wallet_body.id)
                .await;
    } else {
        _create_org_registry_contract(
            &nchain,
            KOVAN_TESTNET_NETWORK_ID,
            &create_wallet_body.id,
            &registry_contract_address,
        )
        .await;
    }

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let workgroup_id: String;
    let workgroup_access_token: String;

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

        std::thread::sleep(std::time::Duration::from_secs(10));

        let create_app_params = json!({
            "network_id": KOVAN_TESTNET_NETWORK_ID,
            "name": format!("{} application", Name().fake::<String>()),
            "type": "baseline",
        });

        ident.token = org_access_token.clone();

        let create_app_res = ident
            .create_application(Some(create_app_params))
            .await
            .expect("create app res");
        assert_eq!(create_app_res.status(), 201);

        let create_app_body = create_app_res
            .json::<Application>()
            .await
            .expect("create app body");

        let application_authorization_params = json!({
            "application_id": &create_app_body.id,
            "scope": "offline_access",
        });
        let application_authorization_res = ident
            .authenticate_application(Some(application_authorization_params))
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
        workgroup_access_token = app_access_token;

        // yaml config file
        let config_file_contents = format!(
            "access-token: {}\nrefresh-token: {}\n{}:\n  api-token: {}\n",
            &user_access_token, &user_refresh_token, &create_app_body.id, &workgroup_access_token
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
        run_cmd += &format!(" --nchain-network-id={}", KOVAN_TESTNET_NETWORK_ID);
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
        run_cmd += &format!(" --workgroup={}", &create_app_body.id);
        run_cmd += &format!(
            " --postgres-hostname={}-postgres",
            &create_organization_body.name
        );
        run_cmd += &format!(" --postgres-port={}", "5433");

        let key_str = r"\n-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqU/GXp8MqmugQyRk5FUF\nBvlJt1/h7L3Crzlzejz/OxriZdq/lBNQW9S1kzGc7qjXprZ1Kg3zP6irr6wmvP0W\nYBGltWs2cWUAmxh0PSxuKdT/OyL9w+rjKLh4yo3ex6DX3Ij0iP01Ej2POe5WrPDS\n8j6LT0s4HZ1FprL5h7RUQWV3cO4pF+1kl6HlBpNzEQzocW9ig4DNdSeUENARHWoC\nixE1gFYo9RXm7acqgqCk3ihdJRIbO4e/m1aZq2mvAFK+yHTIWBL0p5PF0Fe8zcWd\nNeEATYB+eRdNJ3jjS8447YrcbQcBQmhFjk8hbCnc3Rv3HvAapk8xDFhImdVF1ffD\nFwIDAQAB\n-----END PUBLIC KEY-----";
        run_cmd += &format!(" --jwt-signer-public-key='{}'", &key_str);
        run_cmd += " --elasticsearch-ssl-insecure";

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

        std::thread::sleep(Duration::from_secs(20));

        // FIXME-- refactor ApiClient::new to not default to scheme://host/path but instead scheme::/hostpath
        let mut baseline_status_client = ApiClient::new("", "", "", "");
        baseline_status_client.set_base_url(&format!(
            "{}://{}",
            std::env::var("BASELINE_API_SCHEME").expect("baseline api scheme"),
            std::env::var("BASELINE_API_HOST").expect("baseline api host")
        ));

        let mut baseline_container_status = String::from("");

        let mut interval = time::interval(Duration::from_millis(1000));

        while baseline_container_status == "" {
            baseline_container_status = match baseline_status_client.get("status", None).await {
                Ok(res) => res.status().to_string(),
                Err(_) => String::from(""),
            };

            interval.tick().await;
        }

        assert_eq!(baseline_container_status, "204 No Content");

        workgroup_id = create_app_body.id;
    } else {
        // create workgroup
        let create_workgroup_body = generate_workgroup(&baseline).await;
        let application_authorization_params = json!({
            "application_id": &create_workgroup_body.id,
            "scope": "offline_access",
        });
        let application_authorization_res = ident
            .authenticate_application(Some(application_authorization_params))
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
        workgroup_access_token = app_access_token;

        let create_subject_account_params = json!({
            "metadata": {
                "network_id": KOVAN_TESTNET_NETWORK_ID,
                "organization_address": &registry_contract_address,
                "organization_id": &create_organization_body.id,
                "organization_refresh_token": &org_refresh_token,
                "registry_contract_address": &registry_contract_address,
                "workgroup_id": &create_workgroup_body.id,
            }
        });

        let create_subject_account_res = baseline
            .create_subject_account(
                &create_organization_body.id,
                Some(create_subject_account_params),
            )
            .await
            .expect("create subject account response");
        assert_eq!(
            create_subject_account_res.status(),
            201,
            "create subject account res: {}",
            serde_json::to_string_pretty(
                &create_subject_account_res.json::<Value>().await.unwrap()
            )
            .unwrap()
        );

        let update_organization_params = json!({
            "metadata": {
                "address": &org_address,
                "workgroups": {
                    &create_workgroup_body.id: {
                        "operator_separation_degree": 0,
                        "vault_id": &create_organization_vault_res.id,
                    }
                }
            }
        });

        let update_organization_res = ident
            .update_organization(
                &create_organization_body.id,
                Some(update_organization_params),
            )
            .await
            .expect("update organization res");
        assert_eq!(update_organization_res.status(), 204);

        workgroup_id = create_workgroup_body.id;
    }

    let update_workgroup_params = json!({
        "network_id": KOVAN_TESTNET_NETWORK_ID,
        "config": {
            "vault_id": &create_organization_vault_res.id,
            "l2_network_id": POLYGON_MUMBAI_TESTNET_NETWORK_ID,
        }
    });

    let update_workgroup_res = baseline
        .update_workgroup(&workgroup_id, Some(update_workgroup_params))
        .await
        .expect("update workgroup res");
    assert_eq!(update_workgroup_res.status(), 204);

    // json config file
    // TODO: refactor to use memory
    let json_config_params = json!({
        "user_email": &user_email,
        "user_password": &user_password,
        "user_id": &authentication_res_body.user.id,
        "user_access_token": &user_access_token,
        "user_refresh_token": &user_refresh_token,
        "org_access_token": &org_access_token,
        "org_refresh_token": &org_refresh_token,
        "registry_contract_address": &registry_contract_address,
        "org_id": &create_organization_body.id,
        "org_name": &create_organization_body.name,
        "app_access_token": &workgroup_access_token,
        "app_id": &workgroup_id,
    });
    serde_json::to_writer_pretty(
        std::fs::File::create(".test-config.tmp.json")
            .expect("baseline integration suite setup json config"),
        &json_config_params,
    )
    .expect("write json");
}

#[tokio::test]
async fn create_subject_account_fail_with_existing_account() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let org_refresh_token_json = config_vals["org_refresh_token"].to_string();
    let org_refresh_token =
        serde_json::from_str::<String>(&org_refresh_token_json).expect("organzation refresh token");

    let org_id_json = config_vals["org_id"].to_string();
    let org_id = serde_json::from_str::<String>(&org_id_json).expect("organization id");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

    let registry_contract_address_json = config_vals["registry_contract_address"].to_string();
    let registry_contract_address = serde_json::from_str::<String>(&registry_contract_address_json)
        .expect("registry contract address");

    let create_subject_account_params = json!({
        "metadata": {
            "network_id": KOVAN_TESTNET_NETWORK_ID,
            "organization_address": &registry_contract_address,
            "organization_id": &org_id,
            "organization_refresh_token": &org_refresh_token,
            "registry_contract_address": &registry_contract_address,
            "workgroup_id": &app_id,
        }
    });

    let create_subject_account_res = baseline
        .create_subject_account(&org_id, Some(create_subject_account_params))
        .await
        .expect("create subject account response");
    assert_eq!(
        create_subject_account_res.status(),
        409,
        "create subject account fail res: {}",
        serde_json::to_string_pretty(&create_subject_account_res.json::<Value>().await.unwrap())
            .unwrap()
    );
}

#[tokio::test]
async fn create_subject_account_fail_without_workgroup_id() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let org_refresh_token_json = config_vals["org_refresh_token"].to_string();
    let org_refresh_token =
        serde_json::from_str::<String>(&org_refresh_token_json).expect("organzation refresh token");

    let org_id_json = config_vals["org_id"].to_string();
    let org_id = serde_json::from_str::<String>(&org_id_json).expect("organization id");

    let registry_contract_address_json = config_vals["registry_contract_address"].to_string();
    let registry_contract_address = serde_json::from_str::<String>(&registry_contract_address_json)
        .expect("registry contract address");

    let create_subject_account_params = json!({
        "metadata": {
            "network_id": KOVAN_TESTNET_NETWORK_ID,
            "organization_address": &registry_contract_address,
            "organization_id": &org_id,
            "organization_refresh_token": &org_refresh_token,
            "registry_contract_address": &registry_contract_address,
        }
    });

    let create_subject_account_res = baseline
        .create_subject_account(&org_id, Some(create_subject_account_params))
        .await
        .expect("create subject account response");
    assert_eq!(create_subject_account_res.status(), 422);
}

#[tokio::test]
async fn create_subject_account_fail_without_network_id() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let org_refresh_token_json = config_vals["org_refresh_token"].to_string();
    let org_refresh_token =
        serde_json::from_str::<String>(&org_refresh_token_json).expect("organzation refresh token");

    let org_id_json = config_vals["org_id"].to_string();
    let org_id = serde_json::from_str::<String>(&org_id_json).expect("organization id");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

    let registry_contract_address_json = config_vals["registry_contract_address"].to_string();
    let registry_contract_address = serde_json::from_str::<String>(&registry_contract_address_json)
        .expect("registry contract address");

    let create_subject_account_params = json!({
        "metadata": {
            "organization_address": &registry_contract_address,
            "organization_id": &org_id,
            "organization_refresh_token": &org_refresh_token,
            "registry_contract_address": &registry_contract_address,
            "workgroup_id": &app_id,
        }
    });

    let create_subject_account_res = baseline
        .create_subject_account(&org_id, Some(create_subject_account_params))
        .await
        .expect("create subject account response");
    assert_eq!(create_subject_account_res.status(), 422);
}

#[tokio::test]
async fn create_subject_account_fail_without_organization_refresh_token() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let org_id_json = config_vals["org_id"].to_string();
    let org_id = serde_json::from_str::<String>(&org_id_json).expect("organization id");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

    let registry_contract_address_json = config_vals["registry_contract_address"].to_string();
    let registry_contract_address = serde_json::from_str::<String>(&registry_contract_address_json)
        .expect("registry contract address");

    let create_subject_account_params = json!({
        "metadata": {
            "network_id": KOVAN_TESTNET_NETWORK_ID,
            "organization_address": &registry_contract_address,
            "organization_id": &org_id,
            "registry_contract_address": &registry_contract_address,
            "workgroup_id": &app_id,
        }
    });

    let create_subject_account_res = baseline
        .create_subject_account(&org_id, Some(create_subject_account_params))
        .await
        .expect("create subject account response");
    assert_eq!(create_subject_account_res.status(), 422);
}

#[tokio::test]
async fn create_subject_account_fail_without_registry_contract_address() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let org_refresh_token_json = config_vals["org_refresh_token"].to_string();
    let org_refresh_token =
        serde_json::from_str::<String>(&org_refresh_token_json).expect("organzation refresh token");

    let org_id_json = config_vals["org_id"].to_string();
    let org_id = serde_json::from_str::<String>(&org_id_json).expect("organization id");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

    let registry_contract_address_json = config_vals["registry_contract_address"].to_string();
    let registry_contract_address = serde_json::from_str::<String>(&registry_contract_address_json)
        .expect("registry contract address");

    let create_subject_account_params = json!({
        "metadata": {
            "network_id": KOVAN_TESTNET_NETWORK_ID,
            "organization_address": &registry_contract_address,
            "organization_id": &org_id,
            "organization_refresh_token": &org_refresh_token,
            "workgroup_id": &app_id,
        }
    });

    let create_subject_account_res = baseline
        .create_subject_account(&org_id, Some(create_subject_account_params))
        .await
        .expect("create subject account response");
    assert_eq!(create_subject_account_res.status(), 422);
}

#[tokio::test]
async fn create_subject_account_fail_without_organization_address() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let org_refresh_token_json = config_vals["org_refresh_token"].to_string();
    let org_refresh_token =
        serde_json::from_str::<String>(&org_refresh_token_json).expect("organzation refresh token");

    let org_id_json = config_vals["org_id"].to_string();
    let org_id = serde_json::from_str::<String>(&org_id_json).expect("organization id");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

    let registry_contract_address_json = config_vals["registry_contract_address"].to_string();
    let registry_contract_address = serde_json::from_str::<String>(&registry_contract_address_json)
        .expect("registry contract address");

    let create_subject_account_params = json!({
        "metadata": {
            "network_id": KOVAN_TESTNET_NETWORK_ID,
            "organization_id": &org_id,
            "organization_refresh_token": &org_refresh_token,
            "registry_contract_address": &registry_contract_address,
            "workgroup_id": &app_id,
        }
    });

    let create_subject_account_res = baseline
        .create_subject_account(&org_id, Some(create_subject_account_params))
        .await
        .expect("create subject account response");
    assert_eq!(create_subject_account_res.status(), 422);
}

#[tokio::test]
async fn create_subject_account_fail_without_metadata() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let org_id_json = config_vals["org_id"].to_string();
    let org_id = serde_json::from_str::<String>(&org_id_json).expect("organization id");

    let create_subject_account_params = json!({});

    let create_subject_account_res = baseline
        .create_subject_account(&org_id, Some(create_subject_account_params))
        .await
        .expect("create subject account response");
    assert_eq!(create_subject_account_res.status(), 422);
}

#[tokio::test]
async fn create_subject_account_fail_with_id() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let org_refresh_token_json = config_vals["org_refresh_token"].to_string();
    let org_refresh_token =
        serde_json::from_str::<String>(&org_refresh_token_json).expect("organzation refresh token");

    let org_id_json = config_vals["org_id"].to_string();
    let org_id = serde_json::from_str::<String>(&org_id_json).expect("organization id");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

    let registry_contract_address_json = config_vals["registry_contract_address"].to_string();
    let registry_contract_address = serde_json::from_str::<String>(&registry_contract_address_json)
        .expect("registry contract address");

    let create_subject_account_params = json!({
        "id": &org_id,
        "metadata": {
            "network_id": KOVAN_TESTNET_NETWORK_ID,
            "organization_address": &registry_contract_address,
            "organization_id": &org_id,
            "organization_refresh_token": &org_refresh_token,
            "registry_contract_address": &registry_contract_address,
            "workgroup_id": &app_id,
        }
    });

    let create_subject_account_res = baseline
        .create_subject_account(&org_id, Some(create_subject_account_params))
        .await
        .expect("create subject account response");
    assert_eq!(create_subject_account_res.status(), 422);
}

#[tokio::test]
async fn create_subject_account_fail_with_incorrect_subject_id() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let org_refresh_token_json = config_vals["org_refresh_token"].to_string();
    let org_refresh_token =
        serde_json::from_str::<String>(&org_refresh_token_json).expect("organzation refresh token");

    let org_id_json = config_vals["org_id"].to_string();
    let org_id = serde_json::from_str::<String>(&org_id_json).expect("organization id");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

    let registry_contract_address_json = config_vals["registry_contract_address"].to_string();
    let registry_contract_address = serde_json::from_str::<String>(&registry_contract_address_json)
        .expect("registry contract address");

    let create_subject_account_params = json!({
        "id": &org_id,
        "metadata": {
            "network_id": KOVAN_TESTNET_NETWORK_ID,
            "organization_address": &registry_contract_address,
            "organization_id": &org_id,
            "organization_refresh_token": &org_refresh_token,
            "registry_contract_address": &registry_contract_address,
            "workgroup_id": &app_id,
        }
    });

    let create_subject_account_res = baseline
        .create_subject_account(&app_id, Some(create_subject_account_params))
        .await
        .expect("create subject account response");
    assert_eq!(create_subject_account_res.status(), 403);
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let get_mappings_res = baseline
        .list_mappings(None)
        .await
        .expect("get mappings response");
    assert_eq!(get_mappings_res.status(), 200);
}

#[tokio::test]
async fn get_mappings_by_workgroup() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("application id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let get_mappings_res = baseline
        .list_mappings(Some(vec![("workgroup_id".to_string(), app_id)]))
        .await
        .expect("get mappings response");
    assert_eq!(get_mappings_res.status(), 200);
}

#[tokio::test]
async fn create_mapping() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

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
    assert_eq!(
        update_mapping_res.status(),
        204,
        "update mapping res: {}",
        serde_json::to_string_pretty(&update_mapping_res.json::<Value>().await.unwrap()).unwrap()
    );

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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

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
async fn list_workflows() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let get_workflows_res = baseline
        .list_workflows(None)
        .await
        .expect("get workflows response");
    assert_eq!(get_workflows_res.status(), 200);

    // must run tests with full setup twice to test the below
    let workflows = get_workflows_res
        .json::<Vec<Workflow>>()
        .await
        .expect("get workflows body");

    let get_workgroups_res = baseline
        .list_workgroups(None)
        .await
        .expect("get workflows res");
    let workgroups = get_workgroups_res
        .json::<Vec<Workgroup>>()
        .await
        .expect("get workgroups body");

    for workflow in workflows {
        let workflow_workgroup_id = workflow.workgroup_id;

        let mut is_valid = false;
        for workgroup in workgroups.clone() {
            if workflow_workgroup_id == workgroup.id {
                is_valid = true;
            }
        }

        if !is_valid {
            assert!(
                false,
                "incorrect workflow workgroup_id: {}",
                &workflow_workgroup_id
            );
        }
    }
}

#[tokio::test]
async fn get_workflow_prototypes() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        "name": format!("{} workflow instance", Name().fake::<String>()),
        "workflow_id": &create_workflow_body.id,
    });

    let _ = _create_workflow(&baseline, create_workflow_instance_params, 201).await;

    let get_workflows_res = baseline
        .list_workflows(Some(vec![(
            "filter_instances".to_string(),
            "true".to_string(),
        )]))
        .await
        .expect("get workflow prototypes response");
    assert_eq!(get_workflows_res.status(), 200);

    let get_workflow_prototypes_body = get_workflows_res
        .json::<Vec<Workflow>>()
        .await
        .expect("get workflow prototypes body");

    for workflow in get_workflow_prototypes_body {
        if workflow.status != "draft"
            && workflow.status != "pending_deployment"
            && workflow.status != "deployed"
            && workflow.status != "deprecated"
        {
            assert!(
                false,
                "incorrect workflow prototype status: {}",
                &workflow.status
            );
        }
    }
}

#[tokio::test]
async fn get_workflow_instances() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        "name": format!("{} workflow instance", Name().fake::<String>()),
        "workflow_id": &create_workflow_body.id,
    });

    let _ = _create_workflow(&baseline, create_workflow_instance_params, 201).await;

    let get_workflows_res = baseline
        .list_workflows(Some(vec![(
            "filter_prototypes".to_string(),
            "true".to_string(),
        )]))
        .await
        .expect("get workflow instances response");
    assert_eq!(get_workflows_res.status(), 200);

    let get_workflow_instances_body = get_workflows_res
        .json::<Vec<Workflow>>()
        .await
        .expect("get workflow instances body");

    for workflow in get_workflow_instances_body {
        if workflow.status != "init"
            && workflow.status != "running"
            && workflow.status != "completed"
        {
            assert!(
                false,
                "incorrect workflow instance status: {}",
                &workflow.status
            );
        }
    }
}

#[tokio::test]
async fn get_workflows_by_workgroup_id() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        "name": format!("{} workflow instance", Name().fake::<String>()),
        "workflow_id": &create_workflow_body.id,
    });

    let _ = _create_workflow(&baseline, create_workflow_instance_params, 201).await;

    let get_workflows_res = baseline
        .list_workflows(Some(vec![("workgroup_id".to_string(), app_id.clone())]))
        .await
        .expect("get workflows by workgroup id response");
    assert_eq!(get_workflows_res.status(), 200);

    let get_workflows_by_workgroup_id_body = get_workflows_res
        .json::<Vec<Workflow>>()
        .await
        .expect("get workflows by workgroup id body");

    for workflow in get_workflows_by_workgroup_id_body {
        assert_eq!(&workflow.workgroup_id, &app_id)
    }
}

#[tokio::test]
async fn get_workflow_prototypes_by_workgroup_id() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        "name": format!("{} workflow instance", Name().fake::<String>()),
        "workflow_id": &create_workflow_body.id,
    });

    let _ = _create_workflow(&baseline, create_workflow_instance_params, 201).await;

    let get_workflows_res = baseline
        .list_workflows(Some(vec![
            ("workgroup_id".to_string(), app_id.clone()),
            ("filter_instances".to_string(), "true".to_string()),
        ]))
        .await
        .expect("get filtered workflows response");
    assert_eq!(get_workflows_res.status(), 200);

    let get_filtered_workflows_body = get_workflows_res
        .json::<Vec<Workflow>>()
        .await
        .expect("get filtered workflows body");

    for workflow in get_filtered_workflows_body {
        assert_eq!(&workflow.workgroup_id, &app_id);

        if workflow.status != "draft"
            && workflow.status != "deployed"
            && workflow.status != "pending_deployment"
            && workflow.status != "deprecated"
        {
            assert!(
                false,
                "incorrect workflow prototype status: {}",
                &workflow.status
            );
        }
    }
}

#[tokio::test]
async fn get_workflow_instances_by_workgroup_id() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        "name": format!("{} workflow instance", Name().fake::<String>()),
        "workflow_id": &create_workflow_body.id,
    });

    let _ = _create_workflow(&baseline, create_workflow_instance_params, 201).await;

    let get_workflows_res = baseline
        .list_workflows(Some(vec![
            ("workgroup_id".to_string(), app_id.clone()),
            ("filter_prototypes".to_string(), "true".to_string()),
        ]))
        .await
        .expect("get filtered workflows response");
    assert_eq!(get_workflows_res.status(), 200);

    let get_filtered_workflows_body = get_workflows_res
        .json::<Vec<Workflow>>()
        .await
        .expect("get filtered workflows body");

    for workflow in get_filtered_workflows_body {
        assert_eq!(&workflow.workgroup_id, &app_id);

        if workflow.status != "init"
            && workflow.status != "running"
            && workflow.status != "completed"
        {
            assert!(
                false,
                "incorrect workflow instance status: {}",
                &workflow.status
            );
        }
    }
}

#[tokio::test]
async fn get_workflow() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let get_workflow_res = baseline
        .get_workflow(&create_workflow_body.id, None)
        .await
        .expect("get workflow response");
    assert_eq!(get_workflow_res.status(), 200);
}

#[tokio::test]
async fn create_workflow() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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

    let workflow_instance_name = format!("{} workflow instance", Name().fake::<String>());
    let create_workflow_instance_params = json!({
        "workgroup_id": &app_id,
        "name": &workflow_instance_name,
        "workflow_id": &create_workflow_body.id,
        "version": "v0.0.1",
    });

    let create_workflow_instance_body =
        _create_workflow(&baseline, create_workflow_instance_params, 201).await;

    assert_eq!(&create_workflow_instance_body.name, &workflow_instance_name);
    assert_eq!(
        &create_workflow_instance_body
            .version
            .unwrap_or(String::from("")),
        "v0.0.1"
    );
    assert_eq!(&create_workflow_instance_body.workgroup_id, &app_id);
    // TODO: assert workflow_id equality
}

#[tokio::test]
async fn create_workflow_instance_without_version_has_version() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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

    let workflow_instance_name = format!("{} workflow instance", Name().fake::<String>());
    let create_workflow_instance_params = json!({
        "workgroup_id": &app_id,
        "name": &workflow_instance_name,
        "workflow_id": &create_workflow_body.id,
    });

    let create_workflow_instance_body =
        _create_workflow(&baseline, create_workflow_instance_params, 201).await;

    assert_eq!(&create_workflow_instance_body.name, &workflow_instance_name);
    assert_eq!(
        &create_workflow_instance_body
            .version
            .unwrap_or(String::from("")),
        "v0.0.1"
    );
    assert_eq!(&create_workflow_instance_body.workgroup_id, &app_id);
    // TODO: assert workflow_id equality
}

#[tokio::test]
async fn create_workflow_instance_fail_with_new_instance_version() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        "version": "v0.0.2"
    });

    let _ = _create_workflow(&baseline, create_workflow_instance_params, 422).await;
}

#[tokio::test]
async fn create_workflow_instance_worksteps() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        .list_worksteps(&create_workflow_instance_body.id, None)
        .await
        .expect("fetch workflow instance worksteps response");
    assert_eq!(fetch_workflow_instance_worksteps_res.status(), 200);

    let fetch_workflow_instance_worksteps_body = fetch_workflow_instance_worksteps_res
        .json::<Vec<WorkstepInstance>>()
        .await
        .expect("fetch workflow instance worksteps body");

    let worksteps_count = create_workflow_instance_body.worksteps_count.unwrap();
    assert_eq!(
        fetch_workflow_instance_worksteps_body.len(),
        worksteps_count as usize
    );

    for workstep_instance in fetch_workflow_instance_worksteps_body {
        assert_eq!(workstep_instance.status.unwrap(), "init");
    }
}

#[tokio::test]
async fn create_workflow_instance_fail_on_draft_workflow() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "description": "a description",
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let updated_name = format!("{} workflow", Name().fake::<String>());
    let update_workflow_params = json!({
        "name": &updated_name,
        "description": "some updated description",
        "version": "v0.0.2",
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

    let get_updated_workflow_res = baseline
        .get_workflow(&create_workflow_body.id, None)
        .await
        .expect("get updated workflow response");
    assert_eq!(get_updated_workflow_res.status(), 200);

    let get_updated_workflow_body = get_updated_workflow_res
        .json::<Workflow>()
        .await
        .expect("get updated workflow body");

    assert_eq!(&get_updated_workflow_body.name, &updated_name);
    assert_eq!(
        &get_updated_workflow_body.description.unwrap(),
        "some updated description"
    );
    assert_eq!(&get_updated_workflow_body.version.unwrap(), "v0.0.2");
    assert_eq!(&get_updated_workflow_body.status, "draft");
}

#[tokio::test]
async fn update_workflow_fail_on_deployed() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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

    let update_workflow_params = json!({
        "name": format!("{} workflow", Name().fake::<String>()),
        "description": "some updated description",
        "version": "v0.0.2",
        "status": "deployed",
    });

    let update_workflow_res = baseline
        .update_workflow(&create_workflow_body.id, Some(update_workflow_params))
        .await
        .expect("update workflow response");
    assert_eq!(
        update_workflow_res.status(),
        422,
        "update workflow response body: {:?}",
        update_workflow_res.json::<Value>().await.unwrap()
    );
}

#[tokio::test]
async fn deploy_workflow() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
}

#[tokio::test]
async fn deploy_workflow_fail_without_prover_on_all_worksteps() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 422).await;
}

#[tokio::test]
async fn deploy_workflow_fail_without_model_on_all_worksteps() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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
async fn deploy_workflow_fail_without_finality_on_last_workstep() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

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
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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

    let update_workflow_params = json!({
        "name": &create_workflow_body.name,
        "status": "deprecated",
    });
    let update_workflow_res = baseline
        .update_workflow(&create_workflow_body.id, Some(update_workflow_params))
        .await
        .expect("update workflow response");
    assert_eq!(
        update_workflow_res.status(),
        204,
        "update workflow response body {:?}",
        update_workflow_res.json::<Value>().await.unwrap()
    );
}

#[tokio::test]
async fn delete_workflow() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

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

#[tokio::test]
async fn delete_workflow_fail_on_deployed() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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

    let delete_workflow_res = baseline
        .delete_workflow(&create_workflow_body.id)
        .await
        .expect("delete workflow response");
    assert_eq!(
        delete_workflow_res.status(),
        422,
        "delete workflow response body: {:?}",
        delete_workflow_res.json::<Value>().await.unwrap()
    );
}

#[tokio::test]
async fn version_workflow() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let workflow_name = format!("{} workflow", Name().fake::<String>());
    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": &workflow_name,
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    for idx in 0..5 {
        let mut finality = false;
        if idx == 4 {
            finality = true
        }

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

        let create_mapping_body = create_mapping_res
            .json::<Mapping>()
            .await
            .expect("create mapping body");
        let mapping_model = &create_mapping_body.models[0];

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": finality,
            "metadata": {
                "prover": {
                    "identifier": PREIMAGE_HASH_IDENTIFIER,
                    "name": "General Consistency",
                    "provider": GNARK_PROVIDER,
                    "proving_scheme": GROTH16_PROVING_SCHEME,
                    "curve": BLS12_377_CURVE,
                },
                "mapping_model_id": mapping_model.id
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

    let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

    let version_workflow_params = json!({
        "version": "v0.0.2",
    });

    let version_workflow_res = baseline
        .version_workflow(&create_workflow_body.id, Some(version_workflow_params))
        .await
        .expect("version workflow response");
    assert_eq!(
        version_workflow_res.status(),
        201,
        "version workflow response body: {}",
        version_workflow_res.json::<Value>().await.unwrap()
    );

    let version_workflow_body = version_workflow_res
        .json::<Workflow>()
        .await
        .expect("version workflow body");

    assert_eq!(&version_workflow_body.name, &workflow_name);
    assert_eq!(&version_workflow_body.workgroup_id, &app_id);
    assert_eq!(&version_workflow_body.version.unwrap(), "v0.0.2");
    assert_eq!(&version_workflow_body.description, &None);
    assert_eq!(&version_workflow_body.worksteps_count.unwrap(), &5);

    let get_versioned_workflow_worksteps = baseline
        .list_worksteps(&version_workflow_body.id, None)
        .await
        .expect("get versioned workflow worksteps response");
    assert_eq!(get_versioned_workflow_worksteps.status(), 200);

    let get_versioned_workflow_worksteps_body = get_versioned_workflow_worksteps
        .json::<Vec<Workstep>>()
        .await
        .expect("get versioned workflow worksteps body");
    assert_eq!(get_versioned_workflow_worksteps_body.len(), 5);

    for idx in 0..get_versioned_workflow_worksteps_body.len() {
        let workstep = &get_versioned_workflow_worksteps_body[idx];
        assert_eq!(workstep.cardinality, idx + 1);
    }
}

#[tokio::test]
async fn version_workflow_updates_name_and_description() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
        "description": "a workflow description",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    for idx in 0..5 {
        let mut finality = false;
        if idx == 4 {
            finality = true
        }

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

        let create_mapping_body = create_mapping_res
            .json::<Mapping>()
            .await
            .expect("create mapping body");
        let mapping_model = &create_mapping_body.models[0];

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": finality,
            "metadata": {
                "prover": {
                    "identifier": PREIMAGE_HASH_IDENTIFIER,
                    "name": "General Consistency",
                    "provider": GNARK_PROVIDER,
                    "proving_scheme": GROTH16_PROVING_SCHEME,
                    "curve": BLS12_377_CURVE,
                },
                "mapping_model_id": mapping_model.id
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

    let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

    let new_workflow_name = format!("{} versioned workflow", Name().fake::<String>());
    let new_workflow_description = "a newly versioned workflow description".to_string();
    let version_workflow_params = json!({
        "name": &new_workflow_name,
        "description": &new_workflow_description,
        "version": "v0.0.2",
    });

    let version_workflow_res = baseline
        .version_workflow(&create_workflow_body.id, Some(version_workflow_params))
        .await
        .expect("version workflow response");
    assert_eq!(
        version_workflow_res.status(),
        201,
        "version workflow response body: {}",
        version_workflow_res.json::<Value>().await.unwrap()
    );

    let version_workflow_body = version_workflow_res
        .json::<Workflow>()
        .await
        .expect("version workflow body");

    assert_eq!(&version_workflow_body.name, &new_workflow_name);
    assert_eq!(&version_workflow_body.workgroup_id, &app_id);
    assert_eq!(&version_workflow_body.version.unwrap(), "v0.0.2");
    assert_eq!(
        &version_workflow_body
            .description
            .unwrap_or(String::from("")),
        &new_workflow_description
    );
    assert_eq!(&version_workflow_body.worksteps_count.unwrap(), &5);

    let get_versioned_workflow_worksteps = baseline
        .list_worksteps(&version_workflow_body.id, None)
        .await
        .expect("get versioned workflow worksteps response");
    assert_eq!(get_versioned_workflow_worksteps.status(), 200);

    let get_versioned_workflow_worksteps_body = get_versioned_workflow_worksteps
        .json::<Vec<Workstep>>()
        .await
        .expect("get versioned workflow worksteps body");
    assert_eq!(get_versioned_workflow_worksteps_body.len(), 5);

    for idx in 0..get_versioned_workflow_worksteps_body.len() {
        let workstep = &get_versioned_workflow_worksteps_body[idx];
        assert_eq!(workstep.cardinality, idx + 1);
    }
}

#[tokio::test]
async fn version_workflow_fail_on_prototype() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
        "description": "a workflow description",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    for idx in 0..5 {
        let mut finality = false;
        if idx == 4 {
            finality = true
        }

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

        let create_mapping_body = create_mapping_res
            .json::<Mapping>()
            .await
            .expect("create mapping body");
        let mapping_model = &create_mapping_body.models[0];

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": finality,
            "metadata": {
                "prover": {
                    "identifier": PREIMAGE_HASH_IDENTIFIER,
                    "name": "General Consistency",
                    "provider": GNARK_PROVIDER,
                    "proving_scheme": GROTH16_PROVING_SCHEME,
                    "curve": BLS12_377_CURVE,
                },
                "mapping_model_id": mapping_model.id
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

    let version_workflow_params = json!({
        "version": "v0.0.2",
    });

    let version_workflow_res = baseline
        .version_workflow(&create_workflow_body.id, Some(version_workflow_params))
        .await
        .expect("version workflow response");
    assert_eq!(
        version_workflow_res.status(),
        422,
        "version workflow response body: {}",
        version_workflow_res.json::<Value>().await.unwrap()
    );
}

#[tokio::test]
async fn version_workflow_fail_on_versioning_with_same_version() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let workflow_name = format!("{} workflow", Name().fake::<String>());
    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": &workflow_name,
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    for idx in 0..5 {
        let mut finality = false;
        if idx == 4 {
            finality = true
        }

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

        let create_mapping_body = create_mapping_res
            .json::<Mapping>()
            .await
            .expect("create mapping body");
        let mapping_model = &create_mapping_body.models[0];

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": finality,
            "metadata": {
                "prover": {
                    "identifier": PREIMAGE_HASH_IDENTIFIER,
                    "name": "General Consistency",
                    "provider": GNARK_PROVIDER,
                    "proving_scheme": GROTH16_PROVING_SCHEME,
                    "curve": BLS12_377_CURVE,
                },
                "mapping_model_id": mapping_model.id
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

    let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

    let version_workflow_params = json!({
        "version": "v0.0.1",
    });

    let version_workflow_res = baseline
        .version_workflow(&create_workflow_body.id, Some(version_workflow_params))
        .await
        .expect("version workflow response");
    assert_eq!(
        version_workflow_res.status(),
        422,
        "version workflow response body: {}",
        version_workflow_res.json::<Value>().await.unwrap()
    );
}

#[tokio::test]
async fn version_workflow_fail_on_versioning_with_older_version() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let workflow_name = format!("{} workflow", Name().fake::<String>());
    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": &workflow_name,
        "version": "v0.0.2",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    for idx in 0..5 {
        let mut finality = false;
        if idx == 4 {
            finality = true
        }

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

        let create_mapping_body = create_mapping_res
            .json::<Mapping>()
            .await
            .expect("create mapping body");
        let mapping_model = &create_mapping_body.models[0];

        let create_workstep_params = json!({
            "name": format!("{} workstep", Name().fake::<String>()),
            "require_finality": finality,
            "metadata": {
                "prover": {
                    "identifier": PREIMAGE_HASH_IDENTIFIER,
                    "name": "General Consistency",
                    "provider": GNARK_PROVIDER,
                    "proving_scheme": GROTH16_PROVING_SCHEME,
                    "curve": BLS12_377_CURVE,
                },
                "mapping_model_id": mapping_model.id
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

    let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

    let version_workflow_params = json!({
        "version": "v0.0.1",
    });

    let version_workflow_res = baseline
        .version_workflow(&create_workflow_body.id, Some(version_workflow_params))
        .await
        .expect("version workflow response");
    assert_eq!(
        version_workflow_res.status(),
        422,
        "version workflow response body: {}",
        version_workflow_res.json::<Value>().await.unwrap()
    );
}

#[tokio::test]
async fn get_workgroups() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    // let workgroup_name = format!("{} workgroup", Name().fake::<String>());

    // let create_workgroup_params_1 = json!({
    //     "name": &workgroup_name,
    //     "config": {
    //         "onboarding_complete": false
    //     }
    // });

    // let create_workgroup_res = baseline.create_workgroup(Some(create_workgroup_params_1)).await.expect("create workgroup response");
    // assert_eq!(create_workgroup_res.status(), 201);

    // let create_workgroup_params_2 = json!({
    //     "name": &workgroup_name,
    //     "config": {
    //         "onboarding_complete": false
    //     }
    // });

    // let create_workgroup_res = baseline.create_workgroup(Some(create_workgroup_params_2)).await.expect("create workgroup response");
    // assert_eq!(create_workgroup_res.status(), 201);

    // let create_workgroup_params_3 = json!({
    //     "name": &workgroup_name,
    //     "config": {
    //         "onboarding_complete": false
    //     }
    // });

    // let create_workgroup_res = baseline.create_workgroup(Some(create_workgroup_params_3)).await.expect("create workgroup response");
    // assert_eq!(create_workgroup_res.status(), 201);

    let get_workgroups_res = baseline
        .list_workgroups(None)
        .await
        .expect("get workgroups response");
    assert_eq!(get_workgroups_res.status(), 200);

    // let get_workgroups_body = get_workgroups_res.json::<Vec<Workgroup>>().await.expect("get workgroups body");

    // for workgroup in get_workgroups_body.iter() {
    //     // assert_eq!(&workgroup.name, &workgroup_name); // TODO-- add workgroup_id filter to getWorkgroupsHandler
    //     assert_eq!(workgroup.config.as_ref().unwrap()["onboarding_complete"], false);
    // }
}

#[tokio::test]
async fn get_workgroup() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let workgroup_name = format!("{} workgroup", Name().fake::<String>());
    let create_workgroup_params = json!({
        "name": &workgroup_name,
        "config": {
            "onboarding_complete": false
        }
    });

    let create_workgroup_res = baseline
        .create_workgroup(Some(create_workgroup_params))
        .await
        .expect("create workgroup response");
    assert_eq!(create_workgroup_res.status(), 201);

    let create_workgroup_body = create_workgroup_res
        .json::<Workgroup>()
        .await
        .expect("create workgroup body");

    let get_workgroup_res = baseline
        .get_workgroup(&create_workgroup_body.id, None)
        .await
        .expect("get workgroup response");
    assert_eq!(get_workgroup_res.status(), 200);

    let create_workgroup_body = get_workgroup_res
        .json::<Workgroup>()
        .await
        .expect("create workgroup body");

    assert_eq!(create_workgroup_body.name, workgroup_name);
    assert_eq!(
        create_workgroup_body.config.unwrap()["onboarding_complete"],
        false
    );
}

#[tokio::test]
async fn create_workgroup() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let workgroup_name = format!("{} workgroup", Name().fake::<String>());
    let create_workgroup_params = json!({
        "name": &workgroup_name,
        "config": {
            "onboarding_complete": false
        }
    });

    let create_workgroup_res = baseline
        .create_workgroup(Some(create_workgroup_params))
        .await
        .expect("create workgroup response");
    assert_eq!(
        create_workgroup_res.status(),
        201,
        "create workgroup res: {}",
        serde_json::to_string_pretty(&create_workgroup_res.json::<Value>().await.unwrap()).unwrap()
    );

    let create_workgroup_body = create_workgroup_res
        .json::<Workgroup>()
        .await
        .expect("create workgroup body");

    assert_eq!(create_workgroup_body.name, workgroup_name);
    assert_eq!(
        create_workgroup_body.config.unwrap()["onboarding_complete"],
        false
    );
}

#[tokio::test]
async fn update_workgroup() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workgroup_params = json!({
        "name": format!("{} workgroup", Name().fake::<String>()),
    });

    let create_workgroup_res = baseline
        .create_workgroup(Some(create_workgroup_params))
        .await
        .expect("create workgroup response");
    assert_eq!(create_workgroup_res.status(), 201);

    let create_workgroup_body = create_workgroup_res
        .json::<Workgroup>()
        .await
        .expect("create workgroup body");

    let update_workgroup_params = json!({
        "config": {
            "onboarding_complete": false
        }
    });

    let update_workgroup_res = baseline
        .update_workgroup(&create_workgroup_body.id, Some(update_workgroup_params))
        .await
        .expect("update workgroup response");
    assert_eq!(update_workgroup_res.status(), 204);
}

#[tokio::test]
async fn list_worksteps() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let fetch_worksteps_res = baseline
        .list_worksteps(&create_workflow_body.id, None)
        .await
        .expect("fetch worksteps response");
    assert_eq!(fetch_worksteps_res.status(), 200);
}

#[tokio::test]
async fn get_workstep() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let create_workstep_params = json!({ "name": format!("{} workstep", Name().fake::<String>()) });

    let create_workstep_body = _create_workstep(
        &baseline,
        &create_workflow_body.id,
        create_workstep_params,
        201,
    )
    .await;

    let get_workstep_res = baseline
        .get_workstep(&create_workflow_body.id, &create_workstep_body.id, None)
        .await
        .expect("get workstep response");
    assert_eq!(get_workstep_res.status(), 200);
}

#[tokio::test]
async fn create_workstep() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

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
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": null,
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
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

    let updated_workstep_name = format!("{} workstep", Name().fake::<String>());
    let update_workstep_params = json!({
        "name": &updated_workstep_name,
        "description": "an updated workstep description",
        "status": "draft",
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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

    let get_updated_workstep_res = baseline
        .get_workstep(&create_workflow_body.id, &create_workstep_body.id, None)
        .await
        .expect("get updated workstep response");
    assert_eq!(get_updated_workstep_res.status(), 200);

    let get_updated_workstep_body = get_updated_workstep_res
        .json::<Workstep>()
        .await
        .expect("get updated workstep body");

    assert_eq!(&get_updated_workstep_body.name, &updated_workstep_name);
    assert_eq!(
        &get_updated_workstep_body.description.unwrap(),
        "an updated workstep description"
    );
    assert_eq!(&get_updated_workstep_body.status, "draft");
    assert_eq!(&get_updated_workstep_body.require_finality, &true);
    assert_eq!(&get_updated_workstep_body.cardinality, &1);

    let workstep_metadata = get_updated_workstep_body.metadata.unwrap();

    assert_eq!(
        &workstep_metadata["prover"]["identifier"],
        PREIMAGE_HASH_IDENTIFIER
    );
    assert_eq!(&workstep_metadata["prover"]["name"], "General Consistency");
    assert_eq!(&workstep_metadata["prover"]["provider"], GNARK_PROVIDER);
    assert_eq!(
        &workstep_metadata["prover"]["proving_scheme"],
        GROTH16_PROVING_SCHEME
    );
    assert_eq!(&workstep_metadata["prover"]["curve"], BLS12_377_CURVE);
}

#[tokio::test]
async fn update_workstep_cardinality_zero_fail() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
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
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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
async fn update_workstep_fail_on_deployed() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
        },
    });

    let create_workstep_body = _create_workstep(
        &baseline,
        &create_workflow_body.id,
        create_workstep_params,
        201,
    )
    .await;

    let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

    let update_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "description": "an updated workstep description",
        "status": "deployed",
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
async fn update_workstep_move_cardinality_2_worksteps() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
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
        .list_worksteps(&create_workflow_body.id, None)
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
                .get_workstep(&create_workflow_body.id, &current_workstep.id, None)
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
                .get_workstep(&create_workflow_body.id, &current_workstep.id, None)
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
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
        .list_worksteps(&create_workflow_body.id, None)
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
                .get_workstep(&create_workflow_body.id, &current_workstep.id, None)
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
                .get_workstep(&create_workflow_body.id, &current_workstep.id, None)
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
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
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
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
        .get_workflow(&create_workflow_body.id, None)
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
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
        .get_workstep(
            &create_workflow_body.id,
            &create_second_workstep_body.id,
            None,
        )
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workflow", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        .list_worksteps(&create_workflow_instance_body.id, None)
        .await
        .expect("fetch workflow instance worksteps response");
    assert_eq!(fetch_workflow_instance_worksteps_res.status(), 200);

    let fetch_workflow_instance_worksteps_body = fetch_workflow_instance_worksteps_res
        .json::<Vec<WorkstepInstance>>()
        .await
        .expect("fetch workflow instance worksteps body");

    let execute_workstep_params = json!({
        "X": "3",
        "Y": "35"
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
async fn workflow_instance_init_status() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
      "name": format!("{} workstep", Name().fake::<String>()),
      "require_finality": true,
      "metadata": {
          "prover": {
              "identifier": PREIMAGE_HASH_IDENTIFIER,
              "name": "General Consistency",
              "provider": GNARK_PROVIDER,
              "proving_scheme": GROTH16_PROVING_SCHEME,
              "curve": BLS12_377_CURVE,
          },
            "mapping_model_id": mapping_model.id
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

    assert_eq!(create_workflow_instance_body.status, "init");
}

#[tokio::test]
async fn workflow_instance_running_status() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params_1 = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": false,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
        },
    });

    let _ = _create_workstep(
        &baseline,
        &create_workflow_body.id,
        create_workstep_params_1,
        201,
    )
    .await;

    let create_workstep_params_2 = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
        },
    });

    let _ = _create_workstep(
        &baseline,
        &create_workflow_body.id,
        create_workstep_params_2,
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
        .list_worksteps(&create_workflow_instance_body.id, None)
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

    let get_workflow_instance_details_res = baseline
        .get_workflow(&create_workflow_instance_body.id, None)
        .await
        .unwrap();
    let get_workflow_instance_details_body = get_workflow_instance_details_res
        .json::<Workflow>()
        .await
        .unwrap();

    assert_eq!(get_workflow_instance_details_body.status, "running");
}

#[tokio::test]
async fn workflow_instance_completed_status() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        .list_worksteps(&create_workflow_instance_body.id, None)
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

    let get_workflow_instance_details_res = baseline
        .get_workflow(&create_workflow_instance_body.id, None)
        .await
        .unwrap();
    let get_workflow_instance_details_body = get_workflow_instance_details_res
        .json::<Workflow>()
        .await
        .unwrap();

    assert_eq!(get_workflow_instance_details_body.status, "completed");
}

#[tokio::test]
async fn execute_workstep_with_arbitrary_data() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
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
        .list_worksteps(&create_workflow_instance_body.id, None)
        .await
        .expect("fetch workflow instance worksteps response");
    assert_eq!(fetch_workflow_instance_worksteps_res.status(), 200);

    let fetch_workflow_instance_worksteps_body = fetch_workflow_instance_worksteps_res
        .json::<Vec<WorkstepInstance>>()
        .await
        .expect("fetch workflow instance worksteps body");

    let execute_workstep_params = json!({
        "X": "10",
        "Y": "35"
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
async fn execute_workstep_fail_on_draft() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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

#[tokio::test]
async fn fetch_workstep_participants() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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

    let fetch_workstep_participants_res = baseline
        .list_workstep_participants(&create_workflow_body.id, &create_workstep_body.id, None)
        .await
        .expect("fetch workstep participants response");
    assert_eq!(fetch_workstep_participants_res.status(), 200);
}

#[tokio::test]
async fn create_workstep_participant() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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

    let nchain: ApiClient = NChain::factory(&org_access_token);

    let create_account_params = json!({
        "network_id": KOVAN_TESTNET_NETWORK_ID,
    });

    let create_account_res = nchain
        .create_account(Some(create_account_params))
        .await
        .expect("create account response");
    assert_eq!(create_account_res.status(), 201);

    let create_account_body = create_account_res
        .json::<Account>()
        .await
        .expect("create account body");

    // TODO: add other params: proof, witness, witnessed_at, and create WorkstepParticipant struct
    let create_workstep_participant_params = json!({
        "address": &create_account_body.address,
    });

    let create_workstep_participant_res = baseline
        .create_workstep_participant(
            &create_workflow_body.id,
            &create_workstep_body.id,
            Some(create_workstep_participant_params),
        )
        .await
        .expect("create workstep participant response");
    assert_eq!(
        create_workstep_participant_res.status(),
        204,
        "create workstep participant response body: {}",
        create_workstep_participant_res
            .json::<Value>()
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn create_workstep_participant_fail_on_deployed() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
        },
    });

    let create_workstep_body = _create_workstep(
        &baseline,
        &create_workflow_body.id,
        create_workstep_params,
        201,
    )
    .await;

    let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

    let nchain: ApiClient = NChain::factory(&org_access_token);

    let create_account_params = json!({
        "network_id": KOVAN_TESTNET_NETWORK_ID,
    });

    let create_account_res = nchain
        .create_account(Some(create_account_params))
        .await
        .expect("create account response");
    assert_eq!(create_account_res.status(), 201);

    let create_account_body = create_account_res
        .json::<Account>()
        .await
        .expect("create account body");

    // TODO: add other params: proof, witness, witnessed_at
    let create_workstep_participant_params = json!({
        "address": &create_account_body.address,
    });

    let create_workstep_participant_res = baseline
        .create_workstep_participant(
            &create_workflow_body.id,
            &create_workstep_body.id,
            Some(create_workstep_participant_params),
        )
        .await
        .expect("create workstep participant response");
    assert_eq!(
        create_workstep_participant_res.status(),
        400,
        "create workstep participant response body: {}",
        create_workstep_participant_res
            .json::<Value>()
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn delete_workstep_participant() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
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

    let nchain: ApiClient = NChain::factory(&org_access_token);

    let create_account_params = json!({
        "network_id": KOVAN_TESTNET_NETWORK_ID,
    });

    let create_account_res = nchain
        .create_account(Some(create_account_params))
        .await
        .expect("create account response");
    assert_eq!(create_account_res.status(), 201);

    let create_account_body = create_account_res
        .json::<Account>()
        .await
        .expect("create account body");

    // TODO: add other params: proof, witness, witnessed_at
    let create_workstep_participant_params = json!({
        "address": &create_account_body.address,
    });

    let create_workstep_participant_res = baseline
        .create_workstep_participant(
            &create_workflow_body.id,
            &create_workstep_body.id,
            Some(create_workstep_participant_params),
        )
        .await
        .expect("create workstep participant response");
    assert_eq!(
        create_workstep_participant_res.status(),
        204,
        "create workstep participant response body: {}",
        create_workstep_participant_res
            .json::<Value>()
            .await
            .unwrap()
    );

    let delete_workstep_participant_res = baseline
        .delete_workstep_participant(
            &create_workflow_body.id,
            &create_workstep_body.id,
            &create_account_body.address,
        )
        .await
        .expect("delete workstep participant response");
    assert_eq!(
        delete_workstep_participant_res.status(),
        204,
        "delete workstep participant response body: {}",
        delete_workstep_participant_res
            .json::<Value>()
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn delete_workstep_participant_fail_on_deployed() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_workflow_params = json!({
        "workgroup_id": &app_id,
        "name": format!("{} workstep", Name().fake::<String>()),
        "version": "v0.0.1",
    });

    let create_workflow_body = _create_workflow(&baseline, create_workflow_params, 201).await;

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

    let create_mapping_body = create_mapping_res
        .json::<Mapping>()
        .await
        .expect("create mapping body");
    let mapping_model = &create_mapping_body.models[0];

    let create_workstep_params = json!({
        "name": format!("{} workstep", Name().fake::<String>()),
        "require_finality": true,
        "metadata": {
            "prover": {
                "identifier": PREIMAGE_HASH_IDENTIFIER,
                "name": "General Consistency",
                "provider": GNARK_PROVIDER,
                "proving_scheme": GROTH16_PROVING_SCHEME,
                "curve": BLS12_377_CURVE,
            },
            "mapping_model_id": mapping_model.id
        },
    });

    let create_workstep_body = _create_workstep(
        &baseline,
        &create_workflow_body.id,
        create_workstep_params,
        201,
    )
    .await;

    let nchain: ApiClient = NChain::factory(&org_access_token);

    let create_account_params = json!({
        "network_id": KOVAN_TESTNET_NETWORK_ID,
    });

    let create_account_res = nchain
        .create_account(Some(create_account_params))
        .await
        .expect("create account response");
    assert_eq!(create_account_res.status(), 201);

    let create_account_body = create_account_res
        .json::<Account>()
        .await
        .expect("create account body");

    // TODO: add other params: proof, witness, witnessed_at
    let create_workstep_participant_params = json!({
        "address": &create_account_body.address,
    });

    let create_workstep_participant_res = baseline
        .create_workstep_participant(
            &create_workflow_body.id,
            &create_workstep_body.id,
            Some(create_workstep_participant_params),
        )
        .await
        .expect("create workstep participant response");
    assert_eq!(
        create_workstep_participant_res.status(),
        204,
        "create workstep participant response body: {}",
        create_workstep_participant_res
            .json::<Value>()
            .await
            .unwrap()
    );

    let _ = _deploy_workflow(&baseline, &create_workflow_body.id, 202).await;

    let delete_workstep_participant_res = baseline
        .delete_workstep_participant(
            &create_workflow_body.id,
            &create_workstep_body.id,
            &create_account_body.address,
        )
        .await
        .expect("delete workstep participant response");
    assert_eq!(
        delete_workstep_participant_res.status(),
        400,
        "delete workstep participant response body: {}",
        delete_workstep_participant_res
            .json::<Value>()
            .await
            .unwrap()
    );
}

// test passing participant with invalid witness / proof?

// #[tokio::test]
// async fn system_reachability() {}

#[tokio::test]
async fn list_systems() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let fetch_systems_res = baseline
        .list_systems(&app_id, None)
        .await
        .expect("list systems response");
    assert_eq!(fetch_systems_res.status(), 200);
}

#[tokio::test]
async fn get_system_details() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_system_params = json!({
        "type": "sap",
        "name": "test system",
        "auth": {
            "method": "Basic Auth",
            "username": "username",
            "password": "password",
            "require_client_credentials": false,
            "client_id": null,
            "client_secret": null
        },
        "middleware": {
            "inbound": {
                "name": null,
                "url": null,
                "auth": {
                    "method": "Basic Auth",
                    "username": null,
                    "password": null,
                    "require_client_credentials": false,
                    "client_id": null,
                    "client_secret": null
                }
            },
            "outbound": {
                "name": null,
                "url": null,
                "auth": {
                    "method": "Basic Auth",
                    "username": null,
                    "password": null,
                    "require_client_credentials": false,
                    "client_id": null,
                    "client_secret": null
                }
            }
        },
        "endpoint_url": "http://localhost:8070"
    });

    let create_system_res = baseline
        .create_system(&app_id, Some(create_system_params))
        .await
        .expect("create system res");

    let create_system_body = create_system_res
        .json::<System>()
        .await
        .expect("create system body");

    let get_system_details = baseline
        .get_system_details(&app_id, &create_system_body.id, None)
        .await
        .expect("get system details response");
    assert_eq!(get_system_details.status(), 200);
}

#[tokio::test]
async fn create_system() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_system_params = json!({
        "type": "sap",
        "name": "test system",
        "auth": {
            "method": "Basic Auth",
            "username": "username",
            "password": "password",
            "require_client_credentials": false,
            "client_id": null,
            "client_secret": null
        },
        "middleware": {
            "inbound": {
                "name": null,
                "url": null,
                "auth": {
                    "method": "Basic Auth",
                    "username": null,
                    "password": null,
                    "require_client_credentials": false,
                    "client_id": null,
                    "client_secret": null
                }
            },
            "outbound": {
                "name": null,
                "url": null,
                "auth": {
                    "method": "Basic Auth",
                    "username": null,
                    "password": null,
                    "require_client_credentials": false,
                    "client_id": null,
                    "client_secret": null
                }
            }
        },
        "endpoint_url": "http://localhost:8070"
    });

    let create_system_res = baseline
        .create_system(&app_id, Some(create_system_params))
        .await
        .expect("create system res");
    assert_eq!(
        create_system_res.status(),
        201,
        "create system res: {}",
        create_system_res.json::<Value>().await.unwrap()
    );
}

#[tokio::test]
async fn update_system() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_system_params = json!({
        "type": "sap",
        "name": "test system",
        "auth": {
            "method": "Basic Auth",
            "username": "username",
            "password": "password",
            "require_client_credentials": false,
            "client_id": null,
            "client_secret": null
        },
        "middleware": {
            "inbound": {
                "name": null,
                "url": null,
                "auth": {
                    "method": "Basic Auth",
                    "username": null,
                    "password": null,
                    "require_client_credentials": false,
                    "client_id": null,
                    "client_secret": null
                }
            },
            "outbound": {
                "name": null,
                "url": null,
                "auth": {
                    "method": "Basic Auth",
                    "username": null,
                    "password": null,
                    "require_client_credentials": false,
                    "client_id": null,
                    "client_secret": null
                }
            }
        },
        "endpoint_url": "http://localhost:8070"
    });

    let create_system_res = baseline
        .create_system(&app_id, Some(create_system_params))
        .await
        .expect("create system res");
    assert_eq!(create_system_res.status(), 201);

    let create_system_body = create_system_res
        .json::<System>()
        .await
        .expect("create system body");

    let update_system_params = json!({
        "name": "updated system",
    });

    let update_system_res = baseline
        .update_system(&app_id, &create_system_body.id, Some(update_system_params))
        .await
        .expect("update system res");
    assert_eq!(update_system_res.status(), 204);
}

#[tokio::test]
async fn delete_system() {
    let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
    let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

    let org_access_token_json = config_vals["org_access_token"].to_string();
    let org_access_token =
        serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

    let app_id_json = config_vals["app_id"].to_string();
    let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

    let baseline: ApiClient = Baseline::factory(&org_access_token);

    let create_system_params = json!({
        "type": "sap",
        "name": "test system",
        "auth": {
            "method": "Basic Auth",
            "username": "username",
            "password": "password",
            "require_client_credentials": false,
            "client_id": null,
            "client_secret": null
        },
        "middleware": {
            "inbound": {
                "name": null,
                "url": null,
                "auth": {
                    "method": "Basic Auth",
                    "username": null,
                    "password": null,
                    "require_client_credentials": false,
                    "client_id": null,
                    "client_secret": null
                }
            },
            "outbound": {
                "name": null,
                "url": null,
                "auth": {
                    "method": "Basic Auth",
                    "username": null,
                    "password": null,
                    "require_client_credentials": false,
                    "client_id": null,
                    "client_secret": null
                }
            }
        },
        "endpoint_url": "http://localhost:8070"
    });

    let create_system_res = baseline
        .create_system(&app_id, Some(create_system_params))
        .await
        .expect("create system res");
    assert_eq!(create_system_res.status(), 201);

    let create_system_body = create_system_res
        .json::<System>()
        .await
        .expect("create system body");

    let delete_system_res = baseline
        .delete_system(&app_id, &create_system_body.id)
        .await
        .expect("delete system res");
    assert_eq!(
        delete_system_res.status(),
        204,
        "delete system res: {}",
        delete_system_res.json::<Value>().await.unwrap()
    );
}

// #[tokio::test]
// async fn send_protocol_message() {
//     let json_config = std::fs::File::open(".test-config.tmp.json").expect("json config file");
//     let config_vals: Value = serde_json::from_reader(json_config).expect("json config values");

//     let org_access_token_json = config_vals["org_access_token"].to_string();
//     let org_access_token =
//         serde_json::from_str::<String>(&org_access_token_json).expect("organzation access token");

//     let app_id_json = config_vals["app_id"].to_string();
//     let app_id = serde_json::from_str::<String>(&app_id_json).expect("workgroup id");

//     let baseline: ApiClient = Baseline::factory(&org_access_token);

//     let protocol_message_params = json!({
//         "id": "TK421",
//         "type": "Incident2",
//         "workgroup_id": &app_id,
//         "payload": {
//             "id": "TK421"
//         }
//     });

//     let send_protocol_message_res = baseline
//         .send_protocol_message(Some(protocol_message_params))
//         .await
//         .expect("send protocol message res");
//     assert_eq!(
//         send_protocol_message_res.status(),
//         201,
//         "send protocol message res: {:?}",
//         send_protocol_message_res.json::<Value>().await.unwrap()
//     );
// }
