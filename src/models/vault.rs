use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VaultContainer {
    pub id: String,
    created_at: String,
    name: String,
    description: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct UnsealerKey {
    pub key: String,
    validation_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VaultKey {
    pub id: String,
    created_at: String,
    vault_id: String,
    r#type: String,
    usage: String,
    spec: String,
    name: String,
    description: String,
    pub address: Option<String>,
    public_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct EncryptedData {
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VaultSecret {
    pub id: String,
    created_at: String,
    vault_id: String,
    r#type: String,
    name: String,
    description: String,
}
