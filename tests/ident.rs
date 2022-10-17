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

use provide_rust::api::client::ApiClient;
use provide_rust::api::ident::*;
use provide_rust::api::nchain::ROPSTEN_TESTNET_NETWORK_ID;
use provide_rust::api::vault::*;

use fake::{
    faker::{
        internet::en::{FreeEmail, Password},
        name::en::{FirstName, LastName, Name},
    },
    Fake,
};
use serde_json::json;

async fn generate_new_user_and_token() -> AuthenticateResponse {
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

async fn generate_new_application(ident: &ApiClient, user_id: &str) -> Application {
    let application_data = json!({
        "network_id": ROPSTEN_TESTNET_NETWORK_ID,
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

async fn generate_vault(vault: &ApiClient, organization_id: &str) -> VaultContainer {
    let create_vault_params = json!({
        "name": format!("{} {}", Name().fake::<String>(), "Vault"),
        "description": "Some vault description",
        "organization_id": &organization_id,
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

    let ident: ApiClient = Ident::factory(&access_token);

    let get_user_res = ident
        .get_user(
            &authentication_res_body.user.id,
            &authentication_res_body.user.name,
            None,
        )
        .await
        .expect("get user response");
    assert_eq!(get_user_res.status(), 200);
}

#[tokio::test]
async fn list_users() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

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

    let ident: ApiClient = Ident::factory(&access_token);

    let update_params = json!({
        "name": Name().fake::<String>(),
    });
    let update_user_res = ident
        .update_user(
            &authentication_res_body.user.id,
            &authentication_res_body.user.name,
            Some(update_params),
        )
        .await
        .expect("update user response");
    assert_eq!(update_user_res.status(), 204);
}

#[tokio::test]
async fn delete_user() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let delete_user_res = ident
        .delete_user(&authentication_res_body.user.id)
        .await
        .expect("delete user response");
    assert_eq!(delete_user_res.status(), 403);
}

#[tokio::test]
async fn create_organization() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let _ = generate_organization(&ident, &authentication_res_body.user.id).await;
}

#[tokio::test]
async fn list_organizations() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let list_organizations_res = ident
        .list_organizations()
        .await
        .expect("list organizations response");
    assert_eq!(list_organizations_res.status(), 200);
}

#[tokio::test]
async fn get_organization() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let get_organization_res = ident
        .get_organization(&create_organization_body.id)
        .await
        .expect("get organization response");
    assert_eq!(get_organization_res.status(), 200);
}

#[tokio::test]
async fn update_organization() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let update_organization_params = json!({
        "name": "ACME Inc.",
        "description": "Updated description",
        "user_id": &authentication_res_body.user.id,
    });
    let update_organization_res = ident
        .update_organization(
            &create_organization_body.id,
            Some(update_organization_params),
        )
        .await
        .expect("update organization response");
    assert_eq!(update_organization_res.status(), 204);
}

#[tokio::test]
async fn organization_authorization() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let organization_authorization_params = json!({
        "organization_id": create_organization_body.id,
        "scope": "offline_access"
    });
    let organization_authorization_res = ident
        .organization_authorization(Some(organization_authorization_params))
        .await
        .expect("organization authorization response");
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

    let ident: ApiClient = Ident::factory(&access_token);

    let create_organization_params = json!({
        "name": "ACME Inc.",
        "description": "Organization for testing",
        "user_id": &authentication_res_body.user.id,
        "metadata": {
            "hello": "world",
            "arbitrary": "input"
        }
    });
    let create_organization_res = ident
        .create_organization(Some(create_organization_params))
        .await
        .expect("create organization response");
    assert_eq!(create_organization_res.status(), 201);

    let create_organization_body = create_organization_res
        .json::<Organization>()
        .await
        .expect("create organization body");

    let organization_authorization_params = json!({
        "organization_id": create_organization_body.id,
        "scope": "offline_access"
    });
    let organization_authorization_res = ident
        .organization_authorization(Some(organization_authorization_params))
        .await
        .expect("organization authorization response");
    assert_eq!(organization_authorization_res.status(), 201);

    let organization_authorization_body = organization_authorization_res
        .json::<Token>()
        .await
        .expect("organization authorization body");

    let list_tokens_params = json!({
        "refresh_token": organization_authorization_body.refresh_token
    });
    let list_tokens_res = ident
        .list_tokens(Some(list_tokens_params))
        .await
        .expect("list tokens res");
    assert_eq!(list_tokens_res.status(), 200);
}

#[tokio::test]
async fn list_appications() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let list_applications_res = ident
        .list_applications()
        .await
        .expect("list applications response");
    assert_eq!(list_applications_res.status(), 200);
}

#[tokio::test]
async fn create_application() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let _ = generate_new_application(&ident, &authentication_res_body.user.id).await;
}

#[tokio::test]
async fn get_application() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let get_application_res = ident
        .get_application(&create_application_body.id)
        .await
        .expect("get application response");
    assert_eq!(get_application_res.status(), 200);
}

#[tokio::test]
async fn update_application() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let update_application_params = json!({
        "description": "An updated description"
    });
    let update_application_res = ident
        .update_application(&create_application_body.id, Some(update_application_params))
        .await
        .expect("update application response");
    assert_eq!(update_application_res.status(), 204);
}

#[tokio::test]
async fn delete_application() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let delete_application_res = ident
        .delete_application(&create_application_body.id)
        .await
        .expect("delete application response");
    assert_eq!(delete_application_res.status(), 501);
}

#[tokio::test]
async fn list_application_users() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let list_application_users_res = ident
        .list_application_users(&create_application_body.id)
        .await
        .expect("list application users res");
    assert_eq!(list_application_users_res.status(), 200);
}

#[tokio::test]
async fn create_application_user() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let mut ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let application_authorization_params = json!({
        "application_id": create_application_body.id,
        "scope": "offline_access"
    });
    let application_authorization_res = ident
        .application_authorization(Some(application_authorization_params))
        .await
        .expect("application authorization response");
    assert_eq!(application_authorization_res.status(), 201);

    let application_authorization_body = application_authorization_res
        .json::<Token>()
        .await
        .expect("organization authorization body");
    let app_access_token = match application_authorization_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };
    ident.set_bearer_token(&app_access_token);

    let another_user_params = json!({
        "first_name": FirstName().fake::<String>(),
        "last_name": LastName().fake::<String>(),
        "email": FreeEmail().fake::<String>(),
        "password": Password(std::ops::Range { start: 8, end: 15 }).fake::<String>(),
    });
    let create_another_user_res = ident
        .create_user(Some(another_user_params))
        .await
        .expect("create another user response");
    assert_eq!(create_another_user_res.status(), 201);

    let another_user_body = create_another_user_res
        .json::<User>()
        .await
        .expect("another user body");
    let create_application_user_params = json!({
        "user_id": another_user_body.id
    });

    let create_application_user_res = ident
        .create_application_user(
            &create_application_body.id,
            Some(create_application_user_params),
        )
        .await
        .expect("associate application user response");
    assert_eq!(create_application_user_res.status(), 204);
}

#[tokio::test]
async fn application_authorization() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let application_authorization_params = json!({
        "application_id": create_application_body.id,
        "scope": "offline_access"
    });
    let application_authorization_res = ident
        .application_authorization(Some(application_authorization_params))
        .await
        .expect("application authorization response");
    assert_eq!(application_authorization_res.status(), 201);
}

#[tokio::test]
async fn revoke_token() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let application_authorization_params = json!({
        "application_id": create_application_body.id
    });
    let application_authorization_res = ident
        .application_authorization(Some(application_authorization_params))
        .await
        .expect("application authorization response");
    assert_eq!(application_authorization_res.status(), 201);

    let application_authorization_body = application_authorization_res
        .json::<Token>()
        .await
        .expect("application authorization body");

    let revoke_token_res = ident
        .revoke_token(&application_authorization_body.id)
        .await
        .expect("revoke token response");
    assert_eq!(revoke_token_res.status(), 204);
}

#[tokio::test]
async fn create_application_organization() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let mut ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let application_authorization_params = json!({
        "application_id": create_application_body.id,
        "scope": "offline_access"
    });
    let application_authorization_res = ident
        .application_authorization(Some(application_authorization_params))
        .await
        .expect("application authorization response");
    assert_eq!(application_authorization_res.status(), 201);

    let application_authorization_body = application_authorization_res
        .json::<Token>()
        .await
        .expect("organization authorization body");
    let app_access_token = match application_authorization_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };
    ident.set_bearer_token(&app_access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let associate_application_org_params = json!({
        "organization_id": &create_organization_body.id,
    });

    let associate_application_org_res = ident
        .create_application_organization(
            &create_application_body.id,
            Some(associate_application_org_params),
        )
        .await
        .expect("associate application user response");
    assert_eq!(associate_application_org_res.status(), 204);
}

// #[tokio::test]
// async fn fetch_privacy_policy() {}

// #[tokio::test]
// async fn fetch_terms_of_service() {}

#[tokio::test]
async fn request_password_reset() {
    let authentication_res_body = generate_new_user_and_token().await;

    let ident: ApiClient = Ident::factory("");

    let request_password_reset_res = ident
        .request_password_reset(&authentication_res_body.user.email)
        .await
        .expect("request password reset response");
    assert_eq!(request_password_reset_res.status(), 204);
}

// #[tokio::test]
// async fn reset_passwprd() {}

#[tokio::test]
async fn fetch_application_organizations() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let fetch_application_organizations_res = ident
        .fetch_application_organizations(&create_application_body.id)
        .await
        .expect("fetch application organizations response");
    assert_eq!(fetch_application_organizations_res.status(), 200);
}

// #[tokio::test]
// async fn update_application_organization() {
//     let authentication_res_body = generate_new_user_and_token().await;
//     let access_token = match authentication_res_body.token.access_token {
//         Some(string) => string,
//         None => panic!("authentication response access token not found"),
//     };

//     let mut ident: ApiClient = Ident::factory(&access_token);

//     let create_application_body =
//         generate_new_application(&ident, &authentication_res_body.user.id).await;

//     let application_authorization_params = json!({
//         "application_id": create_application_body.id,
//         "scope": "offline_access"
//     });
//     let application_authorization_res = ident
//         .application_authorization(Some(application_authorization_params))
//         .await
//         .expect("application authorization response");
//     assert_eq!(application_authorization_res.status(), 201);

//     let application_authorization_body = application_authorization_res
//         .json::<Token>()
//         .await
//         .expect("organization authorization body");
//     let app_access_token = match application_authorization_body.access_token {
//         Some(string) => string,
//         None => panic!("application authentication response access token not found"),
//     };
//     ident.set_bearer_token(&app_access_token);

//     let create_organization_body =
//         generate_organization(&ident, &authentication_res_body.user.id).await;

//     let associate_application_org_params = json!({
//         "organization_id": &create_organization_body.id,
//     });

//     let associate_application_org_res = ident
//         .create_application_organization(
//             &create_application_body.id,
//             Some(associate_application_org_params),
//         )
//         .await
//         .expect("associate application user response");
//     assert_eq!(associate_application_org_res.status(), 204);

//     let update_application_organization_params = json!({
//         "description": "some updated description",
//     });

//     let update_application_organization_res = ident
//         .update_application_organization(
//             &create_application_body.id,
//             &create_organization_body.id,
//             Some(update_application_organization_params),
//         )
//         .await
//         .expect("update application organization response");
//     assert_eq!(update_application_organization_res.status(), 204);
// }

#[tokio::test]
async fn delete_application_organization() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let mut ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let application_authorization_params = json!({
        "application_id": create_application_body.id,
        "scope": "offline_access"
    });
    let application_authorization_res = ident
        .application_authorization(Some(application_authorization_params))
        .await
        .expect("application authorization response");
    assert_eq!(application_authorization_res.status(), 201);

    let application_authorization_body = application_authorization_res
        .json::<Token>()
        .await
        .expect("organization authorization body");
    let app_access_token = match application_authorization_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };
    ident.set_bearer_token(&app_access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let associate_application_org_params = json!({
        "organization_id": &create_organization_body.id,
    });

    let associate_application_org_res = ident
        .create_application_organization(
            &create_application_body.id,
            Some(associate_application_org_params),
        )
        .await
        .expect("associate application user response");
    assert_eq!(associate_application_org_res.status(), 204);

    let update_application_organization_res = ident
        .delete_application_organization(&create_application_body.id, &create_organization_body.id)
        .await
        .expect("delete application organization response");
    assert_eq!(update_application_organization_res.status(), 204);
}

#[tokio::test]
async fn fetch_application_invitations() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let fetch_application_invitations_res = ident
        .fetch_application_invitations(&create_application_body.id)
        .await
        .expect("fetch application invitations response");
    assert_eq!(fetch_application_invitations_res.status(), 200);
}

#[tokio::test]
async fn fetch_application_tokens() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let fetch_application_tokens_res = ident
        .fetch_application_tokens(&create_application_body.id)
        .await
        .expect("fetch application tokens response");
    assert_eq!(fetch_application_tokens_res.status(), 200);
}

#[tokio::test]
async fn authenticate_application_user() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let mut ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let application_authorization_params = json!({
        "application_id": create_application_body.id,
        "scope": "offline_access"
    });
    let application_authorization_res = ident
        .application_authorization(Some(application_authorization_params))
        .await
        .expect("application authorization response");
    assert_eq!(application_authorization_res.status(), 201);

    let application_authorization_body = application_authorization_res
        .json::<Token>()
        .await
        .expect("organization authorization body");
    let app_access_token = match application_authorization_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };
    ident.set_bearer_token(&app_access_token);

    let app_user = json!({
        "first_name": FirstName().fake::<String>(),
        "last_name": LastName().fake::<String>(),
        "email": FreeEmail().fake::<String>(),
    });
    let create_another_user_res = ident
        .create_user(Some(app_user))
        .await
        .expect("create another user response");
    assert_eq!(create_another_user_res.status(), 201);

    let another_user_body = create_another_user_res
        .json::<User>()
        .await
        .expect("another user body");
    let create_application_user_params = json!({
        "user_id": another_user_body.id
    });

    let create_application_user_res = ident
        .create_application_user(
            &create_application_body.id,
            Some(create_application_user_params),
        )
        .await
        .expect("associate application user response");
    assert_eq!(create_application_user_res.status(), 204);

    let authenticate_application_user = ident
        .authenticate_application_user(&another_user_body.email)
        .await
        .expect("authenticate application user response");
    assert_eq!(authenticate_application_user.status(), 201);
}

// TODO -- add another test to assert that application user can sign in with a password if one is provided, also possibly pass the application id

// #[tokio::test]
// async fn update_application_user() {
//     let authentication_res_body = generate_new_user_and_token().await;
//     let access_token = match authentication_res_body.token.access_token {
//         Some(string) => string,
//         None => panic!("authentication response access token not found"),
//     };

//     let mut ident: ApiClient = Ident::factory(&access_token);

//     let create_application_body =
//         generate_new_application(&ident, &authentication_res_body.user.id).await;

//     let application_authorization_params = json!({
//         "application_id": create_application_body.id,
//         "scope": "offline_access"
//     });
//     let application_authorization_res = ident
//         .application_authorization(Some(application_authorization_params))
//         .await
//         .expect("application authorization response");
//     assert_eq!(application_authorization_res.status(), 201);

//     let application_authorization_body = application_authorization_res
//         .json::<Token>()
//         .await
//         .expect("organization authorization body");
//     let app_access_token = match application_authorization_body.access_token {
//         Some(string) => string,
//         None => panic!("application authentication response access token not found"),
//     };
//     ident.set_bearer_token(&app_access_token);

//     let another_user_params = json!({
//         "first_name": FirstName().fake::<String>(),
//         "last_name": LastName().fake::<String>(),
//         "email": FreeEmail().fake::<String>(),
//         "password": Password(std::ops::Range { start: 8, end: 15 }).fake::<String>(),
//     });
//     let create_another_user_res = ident
//         .create_user(Some(another_user_params))
//         .await
//         .expect("create another user response");
//     assert_eq!(create_another_user_res.status(), 201);

//     let another_user_body = create_another_user_res
//         .json::<User>()
//         .await
//         .expect("another user body");
//     let create_application_user_params = json!({
//         "user_id": another_user_body.id
//     });

//     let create_application_user_res = ident
//         .create_application_user(
//             &create_application_body.id,
//             Some(create_application_user_params),
//         )
//         .await
//         .expect("associate application user response");
//     assert_eq!(create_application_user_res.status(), 204);

//     let update_application_user_params = json!({
//         "name": Name().fake::<String>(),
//     });

//     let update_application_user_response = ident
//         .update_application_user(
//             &create_application_body.id,
//             &another_user_body.id,
//             Some(update_application_user_params),
//         )
//         .await
//         .expect("update application user response");
//     assert_eq!(update_application_user_response.status(), 204);
// }

#[tokio::test]
async fn delete_application_user() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let mut ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let application_authorization_params = json!({
        "application_id": create_application_body.id,
        "scope": "offline_access"
    });
    let application_authorization_res = ident
        .application_authorization(Some(application_authorization_params))
        .await
        .expect("application authorization response");
    assert_eq!(application_authorization_res.status(), 201);

    let application_authorization_body = application_authorization_res
        .json::<Token>()
        .await
        .expect("organization authorization body");
    let app_access_token = match application_authorization_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };
    ident.set_bearer_token(&app_access_token);

    let another_user_params = json!({
        "first_name": FirstName().fake::<String>(),
        "last_name": LastName().fake::<String>(),
        "email": FreeEmail().fake::<String>(),
        "password": Password(std::ops::Range { start: 8, end: 15 }).fake::<String>(),
    });
    let create_another_user_res = ident
        .create_user(Some(another_user_params))
        .await
        .expect("create another user response");
    assert_eq!(create_another_user_res.status(), 201);

    let another_user_body = create_another_user_res
        .json::<User>()
        .await
        .expect("another user body");
    let create_application_user_params = json!({
        "user_id": another_user_body.id
    });

    let create_application_user_res = ident
        .create_application_user(
            &create_application_body.id,
            Some(create_application_user_params),
        )
        .await
        .expect("associate application user response");
    assert_eq!(create_application_user_res.status(), 204);

    let update_application_user_response = ident
        .delete_application_user(&create_application_body.id, &another_user_body.id)
        .await
        .expect("delete application user response");
    assert_eq!(update_application_user_response.status(), 204);
}

#[tokio::test]
async fn fetch_organization_invitations() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let fetch_organization_invitations_res = ident
        .fetch_organization_invitations(&create_organization_body.id)
        .await
        .expect("fetch organization invitations response");
    assert_eq!(fetch_organization_invitations_res.status(), 200);
}

#[tokio::test]
async fn fetch_organization_users() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let fetch_organization_users_res = ident
        .fetch_organization_users(&create_organization_body.id)
        .await
        .expect("fetch organization users response");
    assert_eq!(fetch_organization_users_res.status(), 200);
}

#[tokio::test]
async fn create_organization_user() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let mut ident: ApiClient = Ident::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let organization_authorization_params = json!({
        "organization_id": create_organization_body.id,
        "scope": "offline_access"
    });
    let organization_authorization_res = ident
        .organization_authorization(Some(organization_authorization_params))
        .await
        .expect("organization authorization response");
    assert_eq!(organization_authorization_res.status(), 201);

    let organization_authorization_body = organization_authorization_res
        .json::<Token>()
        .await
        .expect("organization authorization body");
    let org_access_token = match organization_authorization_body.access_token {
        Some(string) => string,
        None => panic!("organization authentication response access token not found"),
    };
    ident.set_bearer_token(&org_access_token);

    let another_user_params = json!({
        "first_name": FirstName().fake::<String>(),
        "last_name": LastName().fake::<String>(),
        "email": FreeEmail().fake::<String>(),
        "password": Password(std::ops::Range { start: 8, end: 15 }).fake::<String>(),
    });
    let create_another_user_res = ident
        .create_user(Some(another_user_params))
        .await
        .expect("create another user response");
    assert_eq!(create_another_user_res.status(), 201);

    let another_user_body = create_another_user_res
        .json::<User>()
        .await
        .expect("another user body");
    let create_organization_user_params = json!({
        "user_id": another_user_body.id
    });

    let create_organization_user_res = ident
        .create_organization_user(
            &create_organization_body.id,
            Some(create_organization_user_params),
        )
        .await
        .expect("associate organization user response");
    assert_eq!(create_organization_user_res.status(), 204);
}

// #[tokio::test]
// async fn update_organization_user() {
//     let authentication_res_body = generate_new_user_and_token().await;
//     let access_token = match authentication_res_body.token.access_token {
//         Some(string) => string,
//         None => panic!("authentication response access token not found"),
//     };

//     let mut ident: ApiClient = Ident::factory(&access_token);

//     let create_organization_body =
//         generate_organization(&ident, &authentication_res_body.user.id).await;

//     let organization_authorization_params = json!({
//         "organization_id": create_organization_body.id,
//         "scope": "offline_access"
//     });
//     let organization_authorization_res = ident
//         .organization_authorization(Some(organization_authorization_params))
//         .await
//         .expect("organization authorization response");
//     assert_eq!(organization_authorization_res.status(), 201);

//     let organization_authorization_body = organization_authorization_res
//         .json::<Token>()
//         .await
//         .expect("organization authorization body");
//     let app_access_token = match organization_authorization_body.access_token {
//         Some(string) => string,
//         None => panic!("organization authentication response access token not found"),
//     };
//     ident.set_bearer_token(&app_access_token);

//     let another_user_params = json!({
//         "first_name": FirstName().fake::<String>(),
//         "last_name": LastName().fake::<String>(),
//         "email": FreeEmail().fake::<String>(),
//         "password": Password(std::ops::Range { start: 8, end: 15 }).fake::<String>(),
//     });
//     let create_another_user_res = ident
//         .create_user(Some(another_user_params))
//         .await
//         .expect("create another user response");
//     assert_eq!(create_another_user_res.status(), 201);

//     let another_user_body = create_another_user_res
//         .json::<User>()
//         .await
//         .expect("another user body");
//     let create_organization_user_params = json!({
//         "user_id": another_user_body.id
//     });

//     let create_organization_user_res = ident
//         .create_organization_user(
//             &create_organization_body.id,
//             Some(create_organization_user_params),
//         )
//         .await
//         .expect("associate organization user response");
//     assert_eq!(create_organization_user_res.status(), 204);

//     let update_organization_user_params = json!({
//         "name": Name().fake::<String>(),
//     });

//     let update_organization_user_response = ident
//         .update_organization_user(
//             &create_organization_body.id,
//             &another_user_body.id,
//             Some(update_organization_user_params),
//         )
//         .await
//         .expect("update organization user response");
//     assert_eq!(update_organization_user_response.status(), 204);
// }

#[tokio::test]
async fn delete_organization_user() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let mut ident: ApiClient = Ident::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let organization_authorization_params = json!({
        "organization_id": create_organization_body.id,
        "scope": "offline_access"
    });
    let organization_authorization_res = ident
        .organization_authorization(Some(organization_authorization_params))
        .await
        .expect("organization authorization response");
    assert_eq!(organization_authorization_res.status(), 201);

    let organization_authorization_body = organization_authorization_res
        .json::<Token>()
        .await
        .expect("organization authorization body");
    let app_access_token = match organization_authorization_body.access_token {
        Some(string) => string,
        None => panic!("organization authentication response access token not found"),
    };
    ident.set_bearer_token(&app_access_token);

    let another_user_params = json!({
        "first_name": FirstName().fake::<String>(),
        "last_name": LastName().fake::<String>(),
        "email": FreeEmail().fake::<String>(),
        "password": Password(std::ops::Range { start: 8, end: 15 }).fake::<String>(),
    });
    let create_another_user_res = ident
        .create_user(Some(another_user_params))
        .await
        .expect("create another user response");
    assert_eq!(create_another_user_res.status(), 201);

    let another_user_body = create_another_user_res
        .json::<User>()
        .await
        .expect("another user body");
    let create_organization_user_params = json!({
        "user_id": another_user_body.id
    });

    let create_organization_user_res = ident
        .create_organization_user(
            &create_organization_body.id,
            Some(create_organization_user_params),
        )
        .await
        .expect("associate organization user response");
    assert_eq!(create_organization_user_res.status(), 204);

    let update_organization_user_response = ident
        .delete_organization_user(&create_organization_body.id, &another_user_body.id)
        .await
        .expect("delete organization user response");
    assert_eq!(update_organization_user_response.status(), 204);
}

#[tokio::test]
async fn fetch_organization_vaults() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let fetch_organization_vaults_res = ident
        .fetch_organization_vaults(&create_organization_body.id)
        .await
        .expect("fetch organization vaults response");
    assert_eq!(fetch_organization_vaults_res.status(), 200);
}

#[tokio::test]
async fn fetch_organization_vault_keys() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);
    let vault: ApiClient = Vault::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let create_organization_vault_body = generate_vault(&vault, &create_organization_body.id).await;

    let fetch_organization_vault_keys_res = ident
        .fetch_organization_vault_keys(
            &create_organization_body.id,
            &create_organization_vault_body.id,
        )
        .await
        .expect("fetch organization vault keys response");
    assert_eq!(fetch_organization_vault_keys_res.status(), 200);
}

// #[tokio::test]
// async fn create_organization_vault_key() {
//     let authentication_res_body = generate_new_user_and_token().await;
//     let access_token = match authentication_res_body.token.access_token {
//         Some(string) => string,
//         None => panic!("authentication response access token not found"),
//     };

//     let ident: ApiClient = Ident::factory(&access_token);
//     let vault: ApiClient = Vault::factory(&access_token);

//     let create_organization_body =
//         generate_organization(&ident, &authentication_res_body.user.id).await;

//     let create_organization_vault_body = generate_vault(&vault, &create_organization_body.id).await;

//     let create_organization_vault_key_params = json!({
//         "type": "symmetric",
//         "usage": "encrypt/decrypt",
//         "spec": "ChaCha20",
//         "name": Name().fake::<String>(),
//         "description": "Some organization key description",
//         "organization_id": &create_organization_body.id,
//     });

//     let create_organization_vault_key_res = ident
//         .create_organization_vault_key(
//             &create_organization_body.id,
//             &create_organization_vault_body.id,
//             Some(create_organization_vault_key_params),
//         )
//         .await
//         .expect("create organization vault key response");
//     assert_eq!(
//         create_organization_vault_key_res.status(),
//         201,
//         "create organization vault key: {}",
//         serde_json::to_string_pretty(
//             &create_organization_vault_key_res
//                 .json::<serde_json::Value>()
//                 .await
//                 .unwrap()
//         )
//         .unwrap()
//     );
// }

// #[tokio::test]
// async fn delete_organization_vault_key() {
//     let authentication_res_body = generate_new_user_and_token().await;
//     let access_token = match authentication_res_body.token.access_token {
//         Some(string) => string,
//         None => panic!("authentication response access token not found"),
//     };

//     let ident: ApiClient = Ident::factory(&access_token);
//     let vault: ApiClient = Vault::factory(&access_token);

//     let create_organization_body =
//         generate_organization(&ident, &authentication_res_body.user.id).await;

//     let create_organization_vault_body = generate_vault(&vault, &create_organization_body.id).await;

//     let create_organization_vault_key_params = json!({
//         "type": "symmetric",
//         "usage": "encrypt/decrypt",
//         "spec": "ChaCha20",
//         "name": Name().fake::<String>(),
//         "description": "Some organization key description",
//         "organization_id": &create_organization_body.id,
//     });

//     let create_organization_vault_key_res = ident
//         .create_organization_vault_key(
//             &create_organization_body.id,
//             &create_organization_vault_body.id,
//             Some(create_organization_vault_key_params),
//         )
//         .await
//         .expect("create organization vault key response");
//     assert_eq!(create_organization_vault_key_res.status(), 201);

//     let create_organization_vault_key_body = create_organization_vault_key_res
//         .json::<VaultKey>()
//         .await
//         .expect("create organization vault key body");

//     let delete_organization_vault_key_res = ident
//         .delete_organization_vault_key(
//             &create_organization_body.id,
//             &create_organization_vault_body.id,
//             &create_organization_vault_key_body.id,
//         )
//         .await
//         .expect("delete organization vault key response");
//     assert_eq!(
//         delete_organization_vault_key_res.status(),
//         204,
//         "delete organization vault key: {}",
//         serde_json::to_string_pretty(
//             &delete_organization_vault_key_res
//                 .json::<serde_json::Value>()
//                 .await
//                 .unwrap()
//         )
//         .unwrap()
//     );
// }

// #[tokio::test]
// async fn organization_vault_key_sign_message() {}

// #[tokio::test]
// async fn organization_vault_key_verify_signature() {}

#[tokio::test]
async fn fetch_organization_vault_secrets() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let ident: ApiClient = Ident::factory(&access_token);
    let vault: ApiClient = Vault::factory(&access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let create_organization_vault_body = generate_vault(&vault, &create_organization_body.id).await;

    let fetch_organization_vault_secrets_res = ident
        .fetch_organization_vault_secrets(
            &create_organization_body.id,
            &create_organization_vault_body.id,
        )
        .await
        .expect("fetch organization vault secrets response");
    assert_eq!(fetch_organization_vault_secrets_res.status(), 200);
}

// #[tokio::test]
// async fn create_organization_vault_secret() {
//     let authentication_res_body = generate_new_user_and_token().await;
//     let access_token = match authentication_res_body.token.access_token {
//         Some(string) => string,
//         None => panic!("authentication response access token not found"),
//     };

//     let ident: ApiClient = Ident::factory(&access_token);
//     let vault: ApiClient = Vault::factory(&access_token);

//     let create_organization_body =
//         generate_organization(&ident, &authentication_res_body.user.id).await;

//     let create_organization_vault_body = generate_vault(&vault, &create_organization_body.id).await;

//     let create_organization_vault_secret_params = json!({
//         "type": "sample secret",
//         "name": Name().fake::<String>(),
//         "description": "this secret is being stored for demonstration purposes",
//         "value": "0x",
//         "organization_id": &create_organization_body.id,
//     });

//     let create_organization_vault_secret_res = ident
//         .create_organization_vault_secret(
//             &create_organization_body.id,
//             &create_organization_vault_body.id,
//             Some(create_organization_vault_secret_params),
//         )
//         .await
//         .expect("create organization vault secret response");
//     assert_eq!(create_organization_vault_secret_res.status(), 201);
// }

// #[tokio::test]
// async fn delete_organization_vault_secret() {
//     let authentication_res_body = generate_new_user_and_token().await;
//     let access_token = match authentication_res_body.token.access_token {
//         Some(string) => string,
//         None => panic!("authentication response access token not found"),
//     };

//     let ident: ApiClient = Ident::factory(&access_token);
//     let vault: ApiClient = Vault::factory(&access_token);

//     let create_organization_body =
//         generate_organization(&ident, &authentication_res_body.user.id).await;

//     let create_organization_vault_body = generate_vault(&vault, &create_organization_body.id).await;

//     let create_organization_vault_secret_params = json!({
//         "type": "sample secret",
//         "name": Name().fake::<String>(),
//         "description": "this secret is being stored for demonstration purposes",
//         "value": "0x",
//         "organization_id": &create_organization_body.id,
//     });

//     let create_organization_vault_secret_res = ident
//         .create_organization_vault_secret(
//             &create_organization_body.id,
//             &create_organization_vault_body.id,
//             Some(create_organization_vault_secret_params),
//         )
//         .await
//         .expect("create organization vault secret response");
//     assert_eq!(create_organization_vault_secret_res.status(), 201);

//     let create_organization_vault_secret_body = create_organization_vault_secret_res
//         .json::<VaultSecret>()
//         .await
//         .expect("create organization vault secret body");

//     let delete_organization_vault_secret_res = ident
//         .delete_organization_vault_secret(
//             &create_organization_body.id,
//             &create_organization_vault_body.id,
//             &create_organization_vault_secret_body.id,
//         )
//         .await
//         .expect("delete organization vault secret response");
//     assert_eq!(delete_organization_vault_secret_res.status(), 204);
// }

// #[tokio::test]
// async fn get_token() {}

// #[tokio::test]
// async fn delete_token() {}

#[tokio::test]
async fn create_invitation() {
    let authentication_res_body = generate_new_user_and_token().await;
    let access_token = match authentication_res_body.token.access_token {
        Some(string) => string,
        None => panic!("authentication response access token not found"),
    };

    let mut ident: ApiClient = Ident::factory(&access_token);

    let create_application_body =
        generate_new_application(&ident, &authentication_res_body.user.id).await;

    let application_authorization_params = json!({
        "application_id": create_application_body.id,
        "scope": "offline_access"
    });
    let application_authorization_res = ident
        .application_authorization(Some(application_authorization_params))
        .await
        .expect("application authorization response");
    assert_eq!(application_authorization_res.status(), 201);

    let application_authorization_body = application_authorization_res
        .json::<Token>()
        .await
        .expect("organization authorization body");
    let app_access_token = match application_authorization_body.access_token {
        Some(string) => string,
        None => panic!("application authentication response access token not found"),
    };
    ident.set_bearer_token(&app_access_token);

    let create_organization_body =
        generate_organization(&ident, &authentication_res_body.user.id).await;

    let associate_application_org_params = json!({
        "organization_id": &create_organization_body.id,
    });

    let associate_application_org_res = ident
        .create_application_organization(
            &create_application_body.id,
            Some(associate_application_org_params),
        )
        .await
        .expect("associate application user response");
    assert_eq!(associate_application_org_res.status(), 204);

    let organization_authorization_params = json!({
        "organization_id": &create_organization_body.id,
        "scope": "offline_access",
    });

    let organization_authorization_res = ident
        .organization_authorization(Some(organization_authorization_params))
        .await
        .expect("organization authorization response");
    assert_eq!(organization_authorization_res.status(), 201);

    let organization_authorization_body = organization_authorization_res
        .json::<Token>()
        .await
        .expect("organization authoziation body");
    ident.set_bearer_token(&organization_authorization_body.access_token.unwrap());

    let name = Name().fake::<String>();
    let invite_first_name = FirstName().fake::<String>();
    let invite_last_name = LastName().fake::<String>();
    let invite_email = FreeEmail().fake::<String>();

    let create_invitation_params = json!({
        "application_id": &create_application_body.id,
        "user_id": &authentication_res_body.user.id,
        "first_name": &invite_first_name,
        "last_name": &invite_last_name,
        "email": &invite_email,
        "organization_id": &create_organization_body.id,
        "organization_name": &create_organization_body.name,
        "permissions": 415,
        "name": &name,
        "invitor_name": &name,
    });

    let create_invitation_res = ident
        .create_invitation(Some(create_invitation_params))
        .await
        .expect("create invitation response");
    assert_eq!(create_invitation_res.status(), 204);

    let fetch_organization_invitations_res = ident
        .fetch_organization_invitations(&create_organization_body.id)
        .await
        .expect("fetch organization invitations response");
    assert_eq!(fetch_organization_invitations_res.status(), 200);
}

// TODO
// seperate application / organization authorization calls are unnecessary
// seperate token struct for ^ response
// rename Token struct or combine all token structs into 1 (enum?)
// seperate generate user and token into 2 helper functions
// create generate organization helper
// the token properties shouldn't be public, should have to occassionally declare pub?
// token enum - beaertoken, accessandresponsetoken, machinetomachine, revokabletoken
// new fn? (as contructor)
// check my pattern w passing references / values through functions
// basically all of these "optional" params (body) are not really optional - change them to required?
// should add required data struct in fn call args, referencing ^
// is it necessary to specifically handle errors differently if req fails?

// how to make these parallel again
// would be nice to use the ? operator instead of unwrapping everything

// how to handle accessing struct keys without making them public
// set function to change client token?
// theres definitely some way to make apiclient a trait and the services a struct, or to implement the services as traits with default method implementations instead of "for ApiClient" (?)
// figure out how to use "?" operator to unwrap

// use this pattern to get val from Option ?
// if let Some(state) = self.state.take() {
// self.state = Some(state.request_review());
// }

// make token optional?

// return futures from service methods?

// type semantics in question
// returning futures from service methods
// making services a struct that wraps client vs traits
// making service arg params structs vs Value, optional?

// use global vars and passing args as config tests for baseline setup vs config file, which sometimes fails

// handlers
// GET    /.well-known/jwks.json                                            ?
// GET    /.well-known/jwks                                                 ?
// GET    /.well-known/keys                                                 ?
// GET    /.well-known/openid-configuration                                 ?
// GET    /.well-known/resolve/:did                                         ?
// GET    /status                                                           X
// GET    /legal/privacy_policy
// GET    /legal/terms_of_service
// POST   /api/v1/authenticate                                              X
// POST   /api/v1/users                                                     X
// POST   /api/v1/users/reset_password
// POST   /api/v1/users/reset_password/:token
// POST   /api/v1/oauth/callback                                            ?
// GET    /api/v1/applications                                              X
// POST   /api/v1/applications                                              X
// GET    /api/v1/applications/:id                                          X
// PUT    /api/v1/applications/:id                                          X
// DELETE /api/v1/applications/:id                                          X
// GET    /api/v1/applications/:id/tokens
// GET    /api/v1/applications/:id/organizations
// POST   /api/v1/applications/:id/organizations                            X
// PUT    /api/v1/applications/:id/organizations/:orgId
// DELETE /api/v1/applications/:id/organizations/:orgId
// GET    /api/v1/applications/:id/users                                    X
// POST   /api/v1/applications/:id/users                                    X
// PUT    /api/v1/applications/:id/users/:userId
// DELETE /api/v1/applications/:id/users/:userId
// GET    /api/v1/applications/:id/invitations
// GET    /api/v1/organizations                                             X
// GET    /api/v1/organizations/:id                                         X
// POST   /api/v1/organizations                                             X
// PUT    /api/v1/organizations/:id                                         X
// DELETE /api/v1/organizations/:id
// GET    /api/v1/organizations/:id/users
// POST   /api/v1/organizations/:id/users
// PUT    /api/v1/organizations/:id/users/:userId
// DELETE /api/v1/organizations/:id/users/:userId
// GET    /api/v1/organizations/:id/invitations
// GET    /api/v1/organizations/:id/vaults
// GET    /api/v1/organizations/:id/vaults/:vaultId/keys
// POST   /api/v1/organizations/:id/vaults/:vaultId/keys
// POST   /api/v1/organizations/:id/vaults/:vaultId/keys/:keyId/sign
// POST   /api/v1/organizations/:id/vaults/:vaultId/keys/:keyId/verify
// GET    /api/v1/organizations/:id/vaults/:vaultId/secrets
// GET    /api/v1/tokens                                                    X
// POST   /api/v1/tokens                                                    X
// DELETE /api/v1/tokens/:id
// GET    /api/v1/users                                                     X
// GET    /api/v1/users/:id                                                 X
// PUT    /api/v1/users/:id                                                 X
// DELETE /api/v1/users/:id                                                 X
// POST   /api/v1/invitations
