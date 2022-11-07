#![allow(dead_code)] // FIXME-- this seems to be a language bug, there is no dead code nor unused imports
#![allow(unused_imports)]

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

use fake::{
    faker::{
        internet::en::{FreeEmail, Password},
        name::en::{FirstName, LastName, Name},
    },
    Fake,
};
use provide_rust::{
    api::{baseline::*, ident::*, nchain::*, vault::*},
    models::{baseline::*, client::*, ident::*, vault::*},
};
use regex::Regex;
use serde_json::json;
use std::io::{Error, ErrorKind};
use std::process::Command;
use std::time::Instant;
use tokio::time::{self, Duration};

pub async fn generate_user_and_token() -> AuthenticateResponse {
    let ident: ApiClient = Ident::factory("");

    let email = FreeEmail().fake::<String>();
    let password = Password(8..15).fake::<String>();

    let user_data = json!({
        "first_name": FirstName().fake::<String>(),
        "last_name": LastName().fake::<String>(),
        "email": &email,
        "password": &password,
    });
    let create_user_res = ident
        .create_user(Some(user_data))
        .await
        .expect("create user response");
    assert_eq!(create_user_res.status(), 201);

    let params = json!({
        "email": &email,
        "password": &password,
        "scope": "offline_access",
    });
    let authenticate_res = ident
        .authenticate(Some(params))
        .await
        .expect("authenticate response");
    assert_eq!(authenticate_res.status(), 201);

    return authenticate_res
        .json::<AuthenticateResponse>()
        .await
        .expect("authentication response body");
}

pub async fn generate_application(ident: &ApiClient, user_id: &str) -> Application {
    let application_data = json!({
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
        "user_id": user_id,
        "name": format!("{} application", Name().fake::<String>()),
        "description": "Some application description",
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

pub async fn generate_application_auth(ident: &ApiClient, application_id: &str) -> Token {
    let application_authorization_params = Some(json!({
        "application_id": application_id,
        "scope": "offline_access",
    }));

    let application_auth_res = ident
        .authenticate_application(application_authorization_params)
        .await
        .expect("application authorization response");
    assert_eq!(application_auth_res.status(), 201);

    return application_auth_res
        .json::<Token>()
        .await
        .expect("application authorization body");
}

pub async fn generate_organization(ident: &ApiClient, user_id: &str) -> Organization {
    let create_organization_params = Some(json!({
        "name": format!("{} organization", Name().fake::<String>()),
        "description": "Organization for testing",
        "user_id": user_id,
        "metadata": {
            "hello": "world",
            "arbitrary": "input"
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

pub async fn generate_organization_auth(ident: &ApiClient, organization_id: &str) -> Token {
    let organization_authorization_params = Some(json!({
        "organization_id": organization_id,
        "scope": "offline_access",
    }));

    let organization_auth_res = ident
        .authenticate_organization(organization_authorization_params)
        .await
        .expect("organization authorization response");
    assert_eq!(organization_auth_res.status(), 201);

    return organization_auth_res
        .json::<Token>()
        .await
        .expect("organization authorization body");
}

pub async fn generate_vault(vault: &ApiClient) -> VaultContainer {
    let create_vault_params = json!({
        "name": format!("{} {}", Name().fake::<String>(), "Vault"),
        "description": "Some vault description",
    });

    let create_vault_res = vault
        .create_vault(Some(create_vault_params))
        .await
        .expect("create vault response");
    assert_eq!(create_vault_res.status(), 201);

    return create_vault_res
        .json::<VaultContainer>()
        .await
        .expect("create vault response");
}

pub async fn generate_workgroup(baseline: &ApiClient) -> Workgroup {
    let workgroup_params = json!({
        "network_id": SEPOLIA_TESTNET_NETWORK_ID,
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

pub async fn get_container_hash(container_re: Regex) -> Result<String, Error> {
    let dps_raw = Command::new("docker")
        .arg("ps")
        .output()
        .expect("docker ps");

    let dps_str = std::str::from_utf8(&dps_raw.stdout[..]).expect("docker ps output str");

    let split_dps_re = Regex::new(r"\r?\n|\r|\n").unwrap();
    let split_dps = split_dps_re.split(dps_str);

    for s in split_dps {
        if container_re.is_match(s) {
            let split_consumer_info_re = Regex::new(r"\s+").unwrap();
            let ident_consumer_container_hash =
                split_consumer_info_re.split(s).collect::<Vec<&str>>()[0];

            return Ok(ident_consumer_container_hash.to_string());
        }
    }

    Err(Error::new(
        ErrorKind::NotFound,
        "failed to find container hash",
    ))
}

pub async fn scrape_invitation_token() -> Result<String, Error> {
    let ident_consumer_re = Regex::new(r"ident\-consumer").unwrap();
    let container_hash = get_container_hash(ident_consumer_re)
        .await
        .expect("ident consumer container hash");

    let mut interval = time::interval(Duration::from_millis(100));
    let now = Instant::now();
    let timeout = Duration::from_secs(5);

    let mut token = String::default();

    while token == "" {
        let logs_raw = Command::new("docker")
            .arg("logs")
            .arg(&container_hash)
            .output()
            .expect("docker logs");

        let logs_str = std::str::from_utf8(&logs_raw.stderr[..]).expect("docker logs output str");

        let token_re = Regex::new(r#"["]dispatch invitation[:] (.*)["]"#).unwrap();

        let matches = token_re.captures_iter(logs_str);
        let collected = matches.collect::<Vec<regex::Captures>>();
        if collected.len() > 0 {
            token = collected[collected.len() - 1]["token"].to_owned()
        } else {
            interval.tick().await;

            if now.elapsed() >= timeout {
                return Err(Error::new(
                    ErrorKind::TimedOut,
                    "failed to find invitation token; scraping timed out",
                ));
            }
        }
    }

    Ok(token)
}
