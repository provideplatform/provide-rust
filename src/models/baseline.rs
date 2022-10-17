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

use crate::models::privacy::Prover;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// pub struct BaselineContext {
// 	id: Option<String>,
// 	baseline_id: Option<String>,
// 	records: Option<Vec<BaselineRecord>>,
// 	workflow: Option<Workflow>,
// 	workflow_id: Option<String>,
// }

// pub struct BaselineRecord {
// 	id: Option<String>,
// 	baseline_id: Option<String>,
// 	context: Option<BaselineContext>,
// 	context_id: Option<String>,
// 	r#type: Option<String>,
// }

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Config {
    env: Option<Value>,
    pub network_id: Option<String>,
    organization_address: Option<String>,
    pub organization_id: Option<String>,
    pub workgroup_id: Option<String>,
    organization_refresh_token: Option<String>,
    registry_contract_address: Option<String>,
}

// pub struct VerifiableCredential {
//     credential: Option<String>,
// }

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Mapping {
    pub id: String,
    created_at: String,

    pub models: Vec<MappingModel>,
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

    default_value: Option<Value>,
    is_primary_key: bool,
    name: String,
    description: Option<String>,
    r#type: String,

    mapping_model_id: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct MappingModel {
    pub id: String,
    created_at: String,

    description: Option<String>,
    fields: Option<Vec<MappingField>>,
    primary_key: Option<String>,
    r#type: Option<String>,

    mapping_id: String,
}

// pub struct Message {
// 	id: Option<String>,
// 	baseline_id: Option<String>,
// 	errors: Value,
// 	message_id: Option<String>,
// 	payload: Value,
// 	protocol_message: Option<ProtocolMessage>,
// 	recipients: Option<Vec<Participant>>,
// 	status: Option<String>,
// 	r#type: Option<String>,
// }

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

// pub struct ProtocolMessage {
//     baseline_id: Option<String>,
//     opcode: Option<String>,
//     sender: Option<String>,
//     recipient: Option<String>,
//     shield: Option<String>,
//     identifier: Option<String>,
//     signature: Option<String>,
//     r#type: Option<String>,
//     payload: Option<ProtocolMessagePayload>,
// }

// pub struct ProtocolMessagePayload {
//     object: Value,
//     proof: Option<String>,
//     r#type: Option<String>,
//     witness: Value,
// }

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Workgroup {
    pub id: String,
    created_at: String,
    pub name: String,
    pub config: Option<Value>,
    participants: Option<Vec<Participant>>,
    workflows: Option<Vec<Workflow>>,
    privacy_policy: Option<Value>,
    security_policy: Option<Value>,
    tokenization_policy: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    created_at: String,
    pub version: Option<String>,
    participants: Option<Vec<Participant>>,
    worksteps: Option<Vec<Workstep>>,
    workflow_id: Option<String>,
    pub status: String,

    updated_at: Option<String>,
    pub workgroup_id: String,
    pub worksteps_count: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WorkflowInstance {
    id: String,
    created_at: String,

    deployed_at: Option<String>,
    metadata: Value,
    participants: Option<Vec<Participant>>,
    shield: Option<String>,
    status: Option<String>,
    version: Option<String>,
    worksteps_count: Option<i32>,

    worksteps: Option<Vec<Workstep>>,
    workflow_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Workstep {
    pub id: String,
    created_at: String,

    pub name: String,
    pub cardinality: usize,
    deployed_at: Option<String>,
    pub metadata: Option<Value>,
    prover: Option<Prover>,
    prover_id: Option<String>,
    participants: Option<Vec<Participant>>,
    pub require_finality: bool,
    shield: Option<String>,
    pub status: String,
    workflow_id: Option<String>,

    pub description: Option<String>,
    workstep_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WorkstepInstance {
    pub id: String,
    created_at: String,

    pub name: String,
    pub cardinality: usize,
    deployed_at: Option<String>,
    metadata: Option<Value>,
    prover: Option<Prover>,
    prover_id: Option<String>,
    participants: Option<Vec<Participant>>,
    require_finality: bool,
    shield: Option<String>,
    pub status: Option<String>,
    workflow_id: Option<String>,

    workstep_id: Option<String>,
}

// subject is organization, application or user
// bpi account is workgroups

// no business objects or objects

// #[derive(Serialize, Deserialize, Debug, Default, Clone)]
// pub struct BpiAccount {

// }

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct System {
    pub id: String,
    created_at: String,

    pub name: String,
    description: Option<String>,
    r#type: String,
    organization_id: String,
    workgroup_id: String,

    auth: Option<SystemAuth>,
    endpoint_url: String,
    middleware: Option<SystemMiddleware>,

    vault_id: Option<String>,
    secret_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SystemAuth {
    method: Option<String>,
    username: Option<String>,
    password: Option<String>,

    require_client_credentials: Option<bool>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SystemMiddlewarePolicy {
    auth: Option<SystemAuth>,
    name: Option<String>,
    url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SystemMiddleware {
    inbound: Option<SystemMiddlewarePolicy>,
    outbound: Option<SystemMiddlewarePolicy>,
}
