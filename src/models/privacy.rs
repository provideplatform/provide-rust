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

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Prover {
    pub id: String,
    created_at: String,

    pub name: String,
    description: Option<String>,
    pub identifier: Option<String>,
    provider: Option<String>,
    proving_scheme: Option<String>,
    curve: Option<String>,
    pub status: Option<String>,

    pub note_store_id: Option<String>,
    nullifier_store_id: Option<String>,

    vault_id: String,
    encryption_key_id: Option<String>,
    proving_key_id: Option<String>,
    verifying_key_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Proof {
    pub proof: String,
}
