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

use reqwest;
use serde_json::Value;

// TODO: make properties private?
#[derive(Debug)]
pub struct ApiClient {
    pub client: reqwest::Client,
    pub base_url: String, // string vs &'a str - prolly not because we want these to have static lifetimes
    pub token: String,
}

pub type Response = Result<reqwest::Response, reqwest::Error>;
pub type Params = Option<Value>;
pub type QueryParams = Option<Vec<(String, String)>>;