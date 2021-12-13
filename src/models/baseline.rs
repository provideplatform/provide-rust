use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::models::privacy::Circuit;

pub struct BaselineContext {
	id: Option<String>,
	baseline_id: Option<String>,
	records: Option<Vec<BaselineRecord>>,
	workflow: Option<Workflow>,
	workflow_id: Option<String>,
}

pub struct BaselineRecord {
	id: Option<String>,
	baseline_id: Option<String>,
	context: Option<BaselineContext>,
	context_id: Option<String>,
	r#type: Option<String>,
}

pub struct Config {
	counterparties: Option<Vec<Participant>>,
	env: Value,
	errors: Value,
	network_id: Option<String>,
	organization_address: Option<String>,
	organization_id: Option<String>,
	organization_refresh_token: Option<String>,
	registry_contract_address: Option<String>,
}

pub struct VerifiableCredential {
    credential: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Mapping {
    pub id: String,
    created_at: String,

    models: Option<Vec<MappingModel>>,
    name: String,
    description: Option<String>,
    r#type: Option<String>,

    organization_id: Option<String>,
    workgroup_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct MappingField {
    id: String,
    created_at: String,

    default_value: Value,
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
    fields: Option<Vec<MappingField>>,
    primary_key: Option<String>,
    r#type: Option<String>,

    mapping_id: String,
}

pub struct Message {
	id: Option<String>,
	baseline_id: Option<String>,
	errors: Value,
	message_id: Option<String>,
	payload: Value,
	protocol_message: Option<ProtocolMessage>,
	recipients: Option<Vec<Participant>>,
	status: Option<String>,
	r#type: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Participant {
    address: Option<String>,
    metadata: Value,
    api_endpoint: Option<String>,
    messaging_endpoint: Option<String>,

    workgroups: Option<Vec<Workgroup>>,
    workflows: Option<Vec<Workflow>>,
    worksteps: Option<Vec<Workstep>>,
}


pub struct ProtocolMessage {
    baseline_id: Option<String>,
    opcode: Option<String>,
    sender: Option<String>,
    recipient: Option<String>,
    shield: Option<String>,
    identifier: Option<String>,
    signature: Option<String>,
    r#type: Option<String>,
    payload: Option<ProtocolMessagePayload>,
}

pub struct ProtocolMessagePayload {
    object: Value,
    proof: Option<String>,
    r#type: Option<String>,
    witness: Value,
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
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    created_at: String,
    version: Option<String>,
    participants: Option<Vec<Participant>>,
    worksteps: Option<Vec<Workstep>>,
    workflow_id: Option<String>,
    pub worksteps_count: Option<i16>,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WorkflowInstance {
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
pub struct Workstep {
    pub id: String,
    pub name: String,
    created_at: String,
    circuit: Option<Circuit>,
    circuit_id: Option<String>,
    require_finality: bool,
    workflow_id: Option<String>,
    participants: Option<Vec<Participant>>,
    workstep_id: Option<String>,
    pub cardinality: usize,
    pub status: String,
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