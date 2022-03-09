use async_trait::async_trait;
use serde_json::json;

use crate::api::client::{ApiClient, Params, Response};
pub use crate::models::ident::*;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "ident.provide.services";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait Ident {
    fn factory(token: &str) -> Self;

    async fn create_user(&self, params: Params) -> Response;

    async fn get_user(&self, user_id: &str, name: &str, params: Params) -> Response;

    async fn get_users(&self) -> Response;

    async fn update_user(&self, user_id: &str, name: &str, params: Params) -> Response;

    async fn delete_user(&self, user_id: &str) -> Response;

    async fn authenticate(&self, params: Params) -> Response;

    async fn application_authorization(&self, params: Params) -> Response;

    async fn organization_authorization(&self, params: Params) -> Response;

    async fn list_tokens(&self, params: Params) -> Response;

    async fn revoke_token(&self, token_id: &str) -> Response;

    async fn create_organization(&self, params: Params) -> Response;

    async fn get_organization(&self, organization_id: &str) -> Response;

    async fn list_organizations(&self) -> Response;

    async fn update_organization(&self, organization_id: &str, params: Params) -> Response;

    async fn create_application(&self, params: Params) -> Response;

    async fn get_application(&self, application_id: &str) -> Response;

    async fn list_applications(&self) -> Response;

    async fn update_application(&self, application_id: &str, params: Params) -> Response;

    async fn delete_application(&self, application_id: &str) -> Response;

    async fn list_application_users(&self, application_id: &str) -> Response;

    async fn create_application_user(&self, application_id: &str, params: Params) -> Response;

    async fn create_application_organization(
        &self,
        application_id: &str,
        params: Params,
    ) -> Response;

    async fn fetch_privacy_policy(&self) -> Response;

    async fn fetch_terms_of_service(&self) -> Response;

    async fn request_password_reset(&self, email: &str) -> Response;

    async fn reset_password(&self, token: &str, params: Params) -> Response;

    async fn fetch_application_organizations(&self, application_id: &str) -> Response;

    async fn update_application_organization(
        &self,
        application_id: &str,
        organization_id: &str,
        params: Params,
    ) -> Response;

    async fn delete_application_organization(
        &self,
        application_id: &str,
        organization_id: &str,
    ) -> Response;

    async fn fetch_application_invitations(&self, application_id: &str) -> Response;

    async fn fetch_application_tokens(&self, application_id: &str) -> Response;

    async fn authenticate_application_user(&self, email: &str) -> Response;

    async fn update_application_user(
        &self,
        application_id: &str,
        user_id: &str,
        params: Params,
    ) -> Response;

    async fn delete_application_user(&self, application_id: &str, user_id: &str) -> Response;

    async fn fetch_organization_invitations(&self, organization_id: &str) -> Response;

    async fn fetch_organization_users(&self, organization_id: &str) -> Response;

    async fn create_organization_user(&self, organization_id: &str, params: Params) -> Response;

    async fn update_organization_user(
        &self,
        organization_id: &str,
        user_id: &str,
        params: Params,
    ) -> Response;

    async fn delete_organization_user(&self, organization_id: &str, user_id: &str) -> Response;

    async fn fetch_organization_vaults(&self, organization_id: &str) -> Response;

    async fn fetch_organization_vault_keys(
        &self,
        organization_id: &str,
        vault_id: &str,
    ) -> Response;

    async fn create_organization_vault_key(
        &self,
        organization_id: &str,
        vault_id: &str,
        params: Params,
    ) -> Response;

    async fn delete_organization_vault_key(
        &self,
        organization_id: &str,
        vault_id: &str,
        key_id: &str,
    ) -> Response;

    async fn organization_vault_key_sign_message(
        &self,
        organization_id: &str,
        vault_id: &str,
        key_id: &str,
        message: &str,
    ) -> Response;

    async fn organization_vault_key_verify_signature(
        &self,
        organization_id: &str,
        vault_id: &str,
        key_id: &str,
        message: &str,
        signature: &str,
    ) -> Response;

    async fn fetch_organization_vault_secrets(
        &self,
        organization_id: &str,
        vault_id: &str,
    ) -> Response;

    async fn create_organization_vault_secret(
        &self,
        organization_id: &str,
        vault_id: &str,
        params: Params,
    ) -> Response;

    async fn delete_organization_vault_secret(
        &self,
        organization_id: &str,
        vault_id: &str,
        secret_id: &str,
    ) -> Response;

    async fn get_token(&self, token_id: &str) -> Response;

    async fn delete_token(&self, token_id: &str) -> Response;

    async fn create_invitation(&self, params: Params) -> Response;
}

#[async_trait]
impl Ident for ApiClient {
    fn factory(token: &str) -> Self {
        let scheme = std::env::var("IDENT_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("IDENT_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("IDENT_API_PATH").unwrap_or(String::from(DEFAULT_PATH));

        return ApiClient::new(&scheme, &host, &path, token);
    }

    async fn create_user(&self, params: Params) -> Response {
        return self.post("users", params, None).await;
    }

    async fn authenticate(&self, params: Params) -> Response {
        return self.post("authenticate", params, None).await;
    }

    async fn get_user(&self, user_id: &str, name: &str, params: Params) -> Response {
        let uri = format!("users/{}", user_id);
        let name_header = vec![("name".to_string(), name.to_string())];
        return self.get(&uri, params, Some(name_header), None).await;
    }

    async fn get_users(&self) -> Response {
        return self.get("users", None, None, None).await;
    }

    async fn update_user(&self, user_id: &str, name: &str, params: Params) -> Response {
        let uri = format!("users/{}", user_id);
        let name_header = vec![("name".to_string(), name.to_string())];
        return self.put(&uri, params, Some(name_header)).await;
    }

    async fn delete_user(&self, user_id: &str) -> Response {
        let uri = format!("users/{}", user_id);
        return self.delete(&uri, None, None).await;
    }

    async fn create_organization(&self, params: Params) -> Response {
        return self.post("organizations", params, None).await;
    }

    async fn list_organizations(&self) -> Response {
        return self.get("organizations", None, None, None).await;
    }

    async fn get_organization(&self, organization_id: &str) -> Response {
        let uri = format!("organizations/{}", organization_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn update_organization(&self, organization_id: &str, params: Params) -> Response {
        let uri = format!("organizations/{}", organization_id);
        return self.put(&uri, params, None).await;
    }

    async fn application_authorization(&self, params: Params) -> Response {
        return self.post("tokens", params, None).await;
    }

    async fn organization_authorization(&self, params: Params) -> Response {
        return self.post("tokens", params, None).await;
    }

    async fn list_tokens(&self, params: Params) -> Response {
        return self.get("tokens", params, None, None).await;
    }

    async fn list_applications(&self) -> Response {
        return self.get("applications", None, None, None).await;
    }

    async fn create_application(&self, params: Params) -> Response {
        return self.post("applications", params, None).await;
    }

    async fn get_application(&self, application_id: &str) -> Response {
        let uri = format!("applications/{}", application_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn update_application(&self, application_id: &str, params: Params) -> Response {
        let uri = format!("applications/{}", application_id);
        return self.put(&uri, params, None).await;
    }

    async fn list_application_users(&self, application_id: &str) -> Response {
        let uri = format!("applications/{}/users", application_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn delete_application(&self, application_id: &str) -> Response {
        let uri = format!("applications/{}", application_id);
        return self.delete(&uri, None, None).await;
    }

    async fn create_application_user(&self, application_id: &str, params: Params) -> Response {
        let uri = format!("applications/{}/users", application_id);
        return self.post(&uri, params, None).await;
    }

    async fn revoke_token(&self, token_id: &str) -> Response {
        let uri = format!("tokens/{}", token_id);
        return self.delete(&uri, None, None).await;
    }

    async fn create_application_organization(
        &self,
        application_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!("applications/{}/organizations", application_id);
        return self.post(&uri, params, None).await;
    }

    async fn fetch_privacy_policy(&self) -> Response {
        return self.get("legal/privacy_policy", None, None, None).await;
    }

    async fn fetch_terms_of_service(&self) -> Response {
        return self.get("legal/terms_of_service", None, None, None).await;
    }

    async fn request_password_reset(&self, email: &str) -> Response {
        let params = json!({ "email": email });
        return self.post("reset_password", Some(params), None).await;
    }

    async fn reset_password(&self, token: &str, params: Params) -> Response {
        let uri = format!("reset_password/{}", token);
        return self.post(&uri, params, None).await;
    }

    async fn fetch_application_organizations(&self, application_id: &str) -> Response {
        let uri = format!("applications/{}/organizations", application_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn update_application_organization(
        &self,
        application_id: &str,
        organization_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!(
            "applications/{}/organizations/{}",
            application_id, organization_id
        );
        return self.put(&uri, params, None).await;
    }

    async fn delete_application_organization(
        &self,
        application_id: &str,
        organization_id: &str,
    ) -> Response {
        let uri = format!(
            "applications/{}/organizations/{}",
            application_id, organization_id
        );
        return self.delete(&uri, None, None).await;
    }

    async fn fetch_application_invitations(&self, application_id: &str) -> Response {
        let uri = format!("applications/{}/invitations", application_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn fetch_application_tokens(&self, application_id: &str) -> Response {
        let uri = format!("applications/{}/tokens", application_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn authenticate_application_user(&self, email: &str) -> Response {
        let params = json!({ "email": &email });
        return self.post("authenticate", Some(params), None).await;
    }

    async fn update_application_user(
        &self,
        application_id: &str,
        user_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!("applications/{}/users/{}", application_id, user_id);
        return self.put(&uri, params, None).await;
    }

    async fn delete_application_user(&self, application_id: &str, user_id: &str) -> Response {
        let uri = format!("applications/{}/users/{}", application_id, user_id);
        return self.delete(&uri, None, None).await;
    }

    async fn fetch_organization_invitations(&self, organization_id: &str) -> Response {
        let uri = format!("organizations/{}/invitations", organization_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn fetch_organization_users(&self, organization_id: &str) -> Response {
        let uri = format!("organizations/{}/users", organization_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn create_organization_user(&self, organization_id: &str, params: Params) -> Response {
        let uri = format!("organizations/{}/users", organization_id);
        return self.post(&uri, params, None).await;
    }

    async fn update_organization_user(
        &self,
        organization_id: &str,
        user_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!("organizations/{}/users/{}", organization_id, user_id);
        return self.put(&uri, params, None).await;
    }

    async fn delete_organization_user(&self, organization_id: &str, user_id: &str) -> Response {
        let uri = format!("organizations/{}/users/{}", organization_id, user_id);
        return self.delete(&uri, None, None).await;
    }

    async fn fetch_organization_vaults(&self, organization_id: &str) -> Response {
        let uri = format!("organizations/{}/vaults", organization_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn fetch_organization_vault_keys(
        &self,
        organization_id: &str,
        vault_id: &str,
    ) -> Response {
        let uri = format!("organizations/{}/vaults/{}/keys", organization_id, vault_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn create_organization_vault_key(
        &self,
        organization_id: &str,
        vault_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!("organizations/{}/vaults/{}/keys", organization_id, vault_id);
        return self.post(&uri, params, None).await;
    }

    async fn delete_organization_vault_key(
        &self,
        organization_id: &str,
        vault_id: &str,
        key_id: &str,
    ) -> Response {
        let uri = format!(
            "organizations/{}/vaults/{}/keys/{}",
            organization_id, vault_id, key_id
        );
        return self.delete(&uri, None, None).await;
    }

    async fn organization_vault_key_sign_message(
        &self,
        organization_id: &str,
        vault_id: &str,
        key_id: &str,
        message: &str,
    ) -> Response {
        let uri = format!(
            "organizations/{}/vaults/{}/keys/{}/sign",
            organization_id, vault_id, key_id
        );
        let params = json!({ "message": message });
        return self.post(&uri, Some(params), None).await;
    }

    async fn organization_vault_key_verify_signature(
        &self,
        organization_id: &str,
        vault_id: &str,
        key_id: &str,
        message: &str,
        signature: &str,
    ) -> Response {
        let uri = format!(
            "organizations/{}/vaults/{}/keys/{}/verify",
            organization_id, vault_id, key_id
        );
        let params = json!({ "message": message, "signature": signature });
        return self.post(&uri, Some(params), None).await;
    }

    async fn fetch_organization_vault_secrets(
        &self,
        organization_id: &str,
        vault_id: &str,
    ) -> Response {
        let uri = format!(
            "organizations/{}/vaults/{}/secrets",
            organization_id, vault_id
        );
        return self.get(&uri, None, None, None).await;
    }

    async fn create_organization_vault_secret(
        &self,
        organization_id: &str,
        vault_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!(
            "organizations/{}/vaults/{}/secrets",
            organization_id, vault_id
        );
        return self.post(&uri, params, None).await;
    }

    async fn delete_organization_vault_secret(
        &self,
        organization_id: &str,
        vault_id: &str,
        secret_id: &str,
    ) -> Response {
        let uri = format!(
            "organizations/{}/vaults/{}/secrets/{}",
            organization_id, vault_id, secret_id
        );
        return self.delete(&uri, None, None).await;
    }

    async fn get_token(&self, token_id: &str) -> Response {
        let uri = format!("tokens/{}", token_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn delete_token(&self, token_id: &str) -> Response {
        let uri = format!("tokens/{}", token_id);
        return self.delete(&uri, None, None).await;
    }

    async fn create_invitation(&self, params: Params) -> Response {
        return self.post("invitations", params, None).await;
    }
}
