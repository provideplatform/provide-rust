use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Account {
    pub id: String,
    created_at: String,
    network_id: String,
    user_id: Option<String>,
    vault_id: String,
    key_id: String,
    public_key: String,
    address: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Connector {
    pub id: String,
    created_at: String,
    application_id: String,
    network_id: String,
    organization_id: Option<String>,
    name: String,
    r#type: String,
    status: String,
    description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ConnectorConfig {
    api_port: i64,
    api_url: String,
    container: String,
    provider_id: String,
    region: String,
    role: String,
    security: Option<ConfigSecurity>,
    target_id: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ConfigSecurity {
    egress: String,
    ingress: Value, // FIXME
}

// #[derive(Serialize, Deserialize, Debug, Default, Clone)]
// pub struct SecurityIngress {
//     r"0.0.0.0/0": IngressParams,
// }

// #[derive(Serialize, Deserialize, Debug, Default, Clone)]
// pub struct IngressParams {
//     tcp: Vec<i64>,
//     udp: Vec<i64>,
// }

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Contract {
    pub id: String,
    created_at: String,
    application_id: String,
    organization_id: Option<String>,
    network_id: String,
    contract_id: Option<String>,
    transaction_id: Option<String>,
    name: String,
    pub address: String,
    r#type: Option<String>,
    accessed_at: Option<String>,
    pubsub_prefix: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Wallet {
    pub id: String,
    created_at: String,
    user_id: Option<String>,
    vault_id: String,
    key_id: String,
    purpose: i64,
    public_key: String,
    application_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Network {
    pub id: String,
    created_at: String,
    user_id: Option<String>,
    name: String,
    description: Option<String>,
    enabled: bool,
    chain_id: String,
    config: Value,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Transaction {
    pub id: String,
    created_at: String,
    network_id: String,
    user_id: String,
    wallet_id: String,
    hd_derivation_path: String,
    to: String,
    value: i64,
    data: Option<Value>,
    hash: String,
    status: String,
    r#ref: Option<Value>,
    description: Option<String>,
    block: Option<Value>,
    broadcast_at: String,
}
