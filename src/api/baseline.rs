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

    async fn get_mappings(&self, query_params: Option<Vec<(String, String)>>) -> Response;

    async fn create_mapping(&self, params: Params) -> Response;

    async fn update_mapping(&self, mapping_id: &str, params: Params) -> Response;

    async fn delete_mapping(&self, mapping_id: &str) -> Response;

    async fn get_config(&self) -> Response;

    async fn update_config(&self, params: Params) -> Response;

    async fn get_workflows(&self, query_params: Option<Vec<(String, String)>>) -> Response;

    async fn get_workflow(&self, workflow_id: &str) -> Response;

    async fn create_workflow(&self, params: Params) -> Response;

    async fn update_workflow(&self, workflow_id: &str, params: Params) -> Response;

    async fn deploy_workflow(&self, workflow_id: &str) -> Response;

    async fn version_workflow(&self, workflow_id: &str, params: Params) -> Response;

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

    async fn fetch_workstep_participants(&self, workflow_id: &str, workstep_id: &str) -> Response;

    async fn create_workstep_participant(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        params: Params,
    ) -> Response;

    async fn delete_workstep_participant(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        participant_address: &str,
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
        return self.get("bpi_accounts", None, None, None).await;
    }

    async fn get_bpi_account(&self, account_id: &str) -> Response {
        let uri = format!("bpi_accounts/{}", account_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn create_bpi_account(&self, params: Params) -> Response {
        return self.post("bpi_accounts", params, None).await;
    }

    async fn create_message(&self, params: Params) -> Response {
        return self.post("protocol_messages", params, None).await;
    }

    async fn get_subjects(&self) -> Response {
        return self.get("subjects", None, None, None).await;
    }

    async fn get_subject(&self, subject_id: &str) -> Response {
        let uri = format!("subjects/{}", subject_id);
        return self.get(&uri, None, None, None).await;
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
        return self.get(&uri, None, None, None).await;
    }

    async fn get_subject_account(&self, subject_id: &str, account_id: &str) -> Response {
        let uri = format!("subjects/{}/accounts/{}", subject_id, account_id);
        return self.get(&uri, None, None, None).await;
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

    async fn get_mappings(&self, query_params: Option<Vec<(String, String)>>) -> Response {
        return self.get("mappings", None, None, query_params).await;
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

    async fn get_config(&self) -> Response {
        return self.get("config", None, None, None).await;
    }

    async fn update_config(&self, params: Params) -> Response {
        return self.put("config", params, None).await;
    }

    async fn get_workflows(&self, query_params: Option<Vec<(String, String)>>) -> Response {
        return self.get("workflows", None, None, query_params).await;
    }

    async fn get_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}", workflow_id);
        return self.get(&uri, None, None, None).await;
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

    async fn version_workflow(&self, workflow_id: &str, params: Params) -> Response {
        let uri = format!("workflows/{}/versions", workflow_id);
        return self.post(&uri, params, None).await;
    }

    async fn get_workgroups(&self) -> Response {
        return self.get("workgroups", None, None, None).await;
    }

    async fn get_workgroup(&self, workgroup_id: &str) -> Response {
        let uri = format!("workgroups/{}", workgroup_id);
        return self.get(&uri, None, None, None).await;
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
        return self.get(&uri, None, None, None).await;
    }

    async fn get_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.get(&uri, None, None, None).await;
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

    async fn fetch_workstep_participants(&self, workflow_id: &str, workstep_id: &str) -> Response {
        let uri = format!(
            "workflows/{}/worksteps/{}/participants",
            workflow_id, workstep_id
        );
        return self.get(&uri, None, None, None).await;
    }

    async fn create_workstep_participant(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!(
            "workflows/{}/worksteps/{}/participants",
            workflow_id, workstep_id
        );
        return self.post(&uri, params, None).await;
    }

    async fn delete_workstep_participant(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        participant_address: &str,
    ) -> Response {
        let uri = format!(
            "workflows/{}/worksteps/{}/participants/{}",
            workflow_id, workstep_id, participant_address
        );
        return self.delete(&uri, None, None).await;
    }
}
