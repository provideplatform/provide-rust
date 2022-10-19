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

use crate::api::client::{ApiClient, Params, QueryParams, Response};
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

    async fn list_bpi_accounts(&self, query_params: QueryParams) -> Response;

    async fn get_bpi_account(&self, account_id: &str, query_params: QueryParams) -> Response;

    async fn create_bpi_account(&self, params: Params) -> Response;

    async fn create_message(&self, params: Params) -> Response;

    async fn list_subjects(&self, query_params: QueryParams) -> Response;

    async fn get_subject(&self, subject_id: &str, query_params: QueryParams) -> Response;

    async fn create_subject(&self, params: Params) -> Response;

    async fn update_subject(&self, subject_id: &str, params: Params) -> Response;

    async fn list_subject_accounts(&self, subject_id: &str, query_params: QueryParams) -> Response;

    async fn get_subject_account(
        &self,
        subject_id: &str,
        account_id: &str,
        query_params: QueryParams,
    ) -> Response;

    async fn create_subject_account(&self, subject_id: &str, params: Params) -> Response;

    async fn update_subject_account(
        &self,
        subject_id: &str,
        account_id: &str,
        params: Params,
    ) -> Response;

    async fn list_mappings(&self, query_params: QueryParams) -> Response;

    async fn create_mapping(&self, params: Params) -> Response;

    async fn update_mapping(&self, mapping_id: &str, params: Params) -> Response;

    async fn delete_mapping(&self, mapping_id: &str) -> Response;

    async fn get_config(&self, query_params: QueryParams) -> Response;

    async fn update_config(&self, params: Params) -> Response;

    async fn list_workflows(&self, query_params: QueryParams) -> Response;

    async fn get_workflow(&self, workflow_id: &str, query_params: QueryParams) -> Response;

    async fn create_workflow(&self, params: Params) -> Response;

    async fn update_workflow(&self, workflow_id: &str, params: Params) -> Response;

    async fn deploy_workflow(&self, workflow_id: &str) -> Response;

    async fn version_workflow(&self, workflow_id: &str, params: Params) -> Response;

    async fn delete_workflow(&self, workflow_id: &str) -> Response;

    async fn list_workgroups(&self, query_params: QueryParams) -> Response;

    async fn get_workgroup(&self, workgroup_id: &str, query_params: QueryParams) -> Response;

    async fn create_workgroup(&self, params: Params) -> Response;

    async fn update_workgroup(&self, workgroup_id: &str, params: Params) -> Response;

    async fn list_worksteps(&self, workflow_id: &str, query_params: QueryParams) -> Response;

    async fn get_workstep(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        query_params: QueryParams,
    ) -> Response;

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

    async fn list_workstep_participants(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        query_params: QueryParams,
    ) -> Response;

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

    async fn system_reachability(&self, params: Params) -> Response;

    async fn list_systems(
        &self,
        workgroup_id: &str,
        query_params: Option<Vec<(String, String)>>,
    ) -> Response;

    async fn get_system_details(
        &self,
        workgroup_id: &str,
        system_id: &str,
        query_params: Option<Vec<(String, String)>>,
    ) -> Response;

    async fn create_system(&self, workgroup_id: &str, params: Params) -> Response;

    async fn update_system(&self, workgroup_id: &str, system_id: &str, params: Params) -> Response;

    async fn delete_system(&self, workgroup_id: &str, system_id: &str) -> Response;

    async fn send_protocol_message(&self, params: Params) -> Response;
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
        return self.post("credentials", params).await;
    }

    async fn create_public_workgroup_invite(&self, params: Params) -> Response {
        return self.post("pub/invite", params).await;
    }

    async fn list_bpi_accounts(&self, query_params: QueryParams) -> Response {
        return self.get("bpi_accounts", query_params).await;
    }

    async fn get_bpi_account(&self, account_id: &str, query_params: QueryParams) -> Response {
        let uri = format!("bpi_accounts/{}", account_id);
        return self.get(&uri, query_params).await;
    }

    async fn create_bpi_account(&self, params: Params) -> Response {
        return self.post("bpi_accounts", params).await;
    }

    async fn create_message(&self, params: Params) -> Response {
        return self.post("protocol_messages", params).await;
    }

    async fn list_subjects(&self, query_params: QueryParams) -> Response {
        return self.get("subjects", query_params).await;
    }

    async fn get_subject(&self, subject_id: &str, query_params: QueryParams) -> Response {
        let uri = format!("subjects/{}", subject_id);
        return self.get(&uri, query_params).await;
    }

    async fn create_subject(&self, params: Params) -> Response {
        return self.post("subjects", params).await;
    }

    async fn update_subject(&self, subject_id: &str, params: Params) -> Response {
        let uri = format!("subjects/{}", subject_id);
        return self.put(&uri, params).await;
    }

    async fn list_subject_accounts(&self, subject_id: &str, query_params: QueryParams) -> Response {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.get(&uri, query_params).await;
    }

    async fn get_subject_account(
        &self,
        subject_id: &str,
        account_id: &str,
        query_params: QueryParams,
    ) -> Response {
        let uri = format!("subjects/{}/accounts/{}", subject_id, account_id);
        return self.get(&uri, query_params).await;
    }

    async fn create_subject_account(&self, subject_id: &str, params: Params) -> Response {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.post(&uri, params).await;
    }

    async fn update_subject_account(
        &self,
        subject_id: &str,
        account_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!("subjects/{}/accounts/{}", subject_id, account_id);
        return self.put(&uri, params).await;
    }

    async fn list_mappings(&self, query_params: QueryParams) -> Response {
        return self.get("mappings", query_params).await;
    }

    async fn create_mapping(&self, params: Params) -> Response {
        return self.post("mappings", params).await;
    }

    async fn update_mapping(&self, mapping_id: &str, params: Params) -> Response {
        let uri = format!("mappings/{}", mapping_id);
        return self.put(&uri, params).await;
    }

    async fn delete_mapping(&self, mapping_id: &str) -> Response {
        let uri = format!("mappings/{}", mapping_id);
        return self.delete(&uri).await;
    }

    async fn get_config(&self, query_params: QueryParams) -> Response {
        return self.get("config", query_params).await;
    }

    async fn update_config(&self, params: Params) -> Response {
        return self.put("config", params).await;
    }

    async fn list_workflows(&self, query_params: QueryParams) -> Response {
        return self.get("workflows", query_params).await;
    }

    async fn get_workflow(&self, workflow_id: &str, query_params: QueryParams) -> Response {
        let uri = format!("workflows/{}", workflow_id);
        return self.get(&uri, query_params).await;
    }

    async fn create_workflow(&self, params: Params) -> Response {
        return self.post("workflows", params).await;
    }

    async fn update_workflow(&self, workflow_id: &str, params: Params) -> Response {
        let uri = format!("workflows/{}", workflow_id);
        return self.put(&uri, params).await;
    }

    async fn deploy_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}/deploy", workflow_id);
        return self.post(&uri, None).await;
    }

    async fn delete_workflow(&self, workflow_id: &str) -> Response {
        let uri = format!("workflows/{}", workflow_id);
        return self.delete(&uri).await;
    }

    async fn version_workflow(&self, workflow_id: &str, params: Params) -> Response {
        let uri = format!("workflows/{}/versions", workflow_id);
        return self.post(&uri, params).await;
    }

    async fn list_workgroups(&self, query_params: QueryParams) -> Response {
        return self.get("workgroups", query_params).await;
    }

    async fn get_workgroup(&self, workgroup_id: &str, query_params: QueryParams) -> Response {
        let uri = format!("workgroups/{}", workgroup_id);
        return self.get(&uri, query_params).await;
    }

    async fn create_workgroup(&self, params: Params) -> Response {
        return self.post("workgroups", params).await;
    }

    async fn update_workgroup(&self, workgroup_id: &str, params: Params) -> Response {
        let uri = format!("workgroups/{}", workgroup_id);
        return self.put(&uri, params).await;
    }

    async fn list_worksteps(&self, workflow_id: &str, query_params: QueryParams) -> Response {
        let uri = format!("workflows/{}/worksteps", workflow_id);
        return self.get(&uri, query_params).await;
    }

    async fn get_workstep(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        query_params: QueryParams,
    ) -> Response {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.get(&uri, query_params).await;
    }

    async fn create_workstep(&self, workflow_id: &str, params: Params) -> Response {
        let uri = format!("workflows/{}/worksteps", workflow_id);
        return self.post(&uri, params).await;
    }

    async fn update_workstep(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        params: Params,
    ) -> Response {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.put(&uri, params).await;
    }

    async fn delete_workstep(&self, workflow_id: &str, workstep_id: &str) -> Response {
        let uri = format!("workflows/{}/worksteps/{}", workflow_id, workstep_id);
        return self.delete(&uri).await;
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
        return self.post(&uri, params).await;
    }

    async fn list_workstep_participants(
        &self,
        workflow_id: &str,
        workstep_id: &str,
        query_params: QueryParams,
    ) -> Response {
        let uri = format!(
            "workflows/{}/worksteps/{}/participants",
            workflow_id, workstep_id
        );
        return self.get(&uri, query_params).await;
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
        return self.post(&uri, params).await;
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
        return self.delete(&uri).await;
    }

    async fn system_reachability(&self, params: Params) -> Response {
        return self.post("systems/reachability", params).await;
    }

    async fn list_systems(
        &self,
        workgroup_id: &str,
        query_params: Option<Vec<(String, String)>>,
    ) -> Response {
        let uri = format!("workgroups/{}/systems", workgroup_id);
        return self.get(&uri, query_params).await;
    }

    async fn get_system_details(
        &self,
        workgroup_id: &str,
        system_id: &str,
        query_params: Option<Vec<(String, String)>>,
    ) -> Response {
        let uri = format!("workgroups/{}/systems/{}", workgroup_id, system_id);
        return self.get(&uri, query_params).await;
    }

    async fn create_system(&self, workgroup_id: &str, params: Params) -> Response {
        let uri = format!("workgroups/{}/systems", workgroup_id);
        return self.post(&uri, params).await;
    }

    async fn update_system(&self, workgroup_id: &str, system_id: &str, params: Params) -> Response {
        let uri = format!("workgroups/{}/systems/{}", workgroup_id, system_id);
        return self.put(&uri, params).await;
    }

    async fn delete_system(&self, workgroup_id: &str, system_id: &str) -> Response {
        let uri = format!("workgroups/{}/systems/{}", workgroup_id, system_id);
        return self.delete(&uri).await;
    }

    async fn send_protocol_message(&self, params: Params) -> Response {
        return self.post("protocol_messages", params).await;
    }
}
