use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Circuit {
    pub id: String,
    created_at: String,
    vault_id: String,
    encryption_key_id: Option<String>,
    proving_key_id: Option<String>,
    verifying_key_id: Option<String>,
    pub name: String,
    description: Option<String>,
    pub identifier: String,
    provider: String,
    proving_scheme: String,
    curve: String,
    pub status: Option<String>,
    pub note_store_id: Option<String>,
    nullifier_store_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Proof {
    pub proof: String,
}