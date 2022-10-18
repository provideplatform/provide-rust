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

use serde::{Deserialize, Serialize};

// change to VaultService so that i can rename VaultContainer to Vault ?
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct VaultContainer {
    pub id: String,
    created_at: String,
    name: String,
    description: Option<String>,
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
