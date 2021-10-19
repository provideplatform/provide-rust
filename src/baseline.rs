pub use crate::client::{ApiClient, AdditionalHeader};
use std::result::{Result};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use serde_json::{Value};

const DEFAULT_SCHEME: &str = "";
const DEFAULT_HOST: &str = "";
const DEFAULT_PATH: &str = "";

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

    async fn get_subject_account(&self, subject_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_subject_account(&self, subject_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_subject_subject_account(&self, subject_id: &str, account_id: &str) -> Result<reqwest::Response, reqwest::Error>;

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

    async fn get_subject_account(&self, subject_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.get(&uri, None, None).await
    }

    async fn create_subject_account(&self, subject_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("subjects/{}/accounts", subject_id);
        return self.post(&uri, params, None).await
    }

    async fn get_subject_subject_account(&self, subject_id: &str, account_id: &str) -> Result<reqwest::Response, reqwest::Error> {
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

#[cfg(test)]
mod tests {}