use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct BpiAccount {
    context: Value, // FIXME: apparently this is @context
    balances: Value,
    created_at: String,
    owners: Value,
    id: String,
    metadata: Value,
    nonce: i64,
    security_policies: Value,
    state_claims: Value,
    workflows: Value,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Subject {
    created_at: String,
    description: String, // this is probably optional
    id: String,
    metadata: Value,
    name: String,
    r#type: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SubjectAccount {
    context: Value, // FIXME: apparently this is @context
    id: String,
    bpi_account_ids: Vec<String>,
    created_at: String,
    credentials: Value,
    metadata: Value,
    r#type: String,
    recovery_policy: Value,
    role: Value,
    subject_id: String,
    security_policies: Value,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Workflow {
    id: String,
    name: String,
    r#type: String,
    workstep_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Workgroup {
    id: String,
    created_at: String,
    subject_id: String,
    config: Value,
    description: String,
    name: String,
    network_id: String,
    r#type: String,
    security_policies: Value,
    admins: Vec<String>,
}