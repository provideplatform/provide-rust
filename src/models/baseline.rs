use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::models::privacy::Circuit;
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
pub struct Workflow {
    id: String,
    created_at: String,
    version: Option<String>,
    participants: Option<Vec<Participant>>,
    worksteps: Option<Vec<Workstep>>,
    workflow_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct  WorkflowInstance {
    id: String,
    created_at: String,
    version: Option<String>,
    participants: Option<Vec<Participant>>,
    worksteps: Option<Vec<Workstep>>,
    workflow_id: Option<String>,
    shield: Option<String>,
    status: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Workgroup {
    id: String,
    created_at: String,
    participants: Option<Vec<Participant>>,
    workflows: Option<Vec<Workflow>>,
    privacy_policy: Option<Value>,
    security_policy: Option<Value>,
    tokenization_policy: Option<Value>,
    name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Participant {
    metadata: Value,
    api_endpoint: Option<String>,
    messaging_endpoint: Option<String>,
    address: Option<String>,
    workgroups: Option<Vec<Workgroup>>,
    workflows: Option<Vec<Workflow>>,
    worksteps: Option<Vec<Workstep>>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Workstep {
    id: String,
    created_at: String,
    circuit: Option<Circuit>,
    circuit_id: Option<String>,
    require_finality: bool,
    workflow_id: Option<String>,
    participants: Option<Vec<Participant>>,
    workstep_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WorkstepInstance {
    id: String,
    created_at: String,
    circuit: Option<Circuit>,
    circuit_id: Option<String>,
    require_finality: bool,
    workflow_id: Option<String>,
    participants: Option<Vec<Participant>>,
    workstep_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Mapping {
    pub id: String,
    created_at: String,
    name: String,
    description: Option<String>,
    r#type: Option<String>,
    models: Option<Vec<MappingModel>>,
    organization_id: Option<String>,
    workgroup_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct MappingField {
    id: String,
    created_at: String,
    default_value: Option<Value>,
    is_primary_key: bool,
    name: String,
    description: Option<String>,
    r#type: String,
    mapping_model_id: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct MappingModel {
    id: String,
    created_at: String,
    description: Option<String>,
    primary_key: Option<String>,
    r#type: Option<String>,
    mapping_id: String,
    fields: Option<Vec<MappingField>>,
}