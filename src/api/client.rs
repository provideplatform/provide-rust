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

pub use crate::models::client::{ApiClient, Params, QueryParams, Response};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
    Client,
};

const DEFAULT_API_USER_AGENT: &str = "provide-rust client library";

impl ApiClient {
    pub fn new(scheme: &str, host: &str, path: &str, token: &str) -> Self {
        let client = Client::new();
        let base_url = format!("{}://{}/{}", scheme, host, path);

        Self {
            client,
            base_url,
            token: token.to_string(),
        }
    }

    pub fn get(
        &self,
        uri: &str,
        query_params: QueryParams,
    ) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .get(url)
            .headers(self.construct_headers("GET"))
            .query(&query_params.unwrap_or(vec![]))
            .send()
    }

    pub fn patch(&self, uri: &str, params: Params) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .patch(url)
            .headers(self.construct_headers("PATCH"))
            .json(&params)
            .send()
    }

    pub fn put(&self, uri: &str, params: Params) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .put(url)
            .headers(self.construct_headers("PUT"))
            .json(&params)
            .send()
    }

    pub fn post(&self, uri: &str, params: Params) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .post(url)
            .headers(self.construct_headers("POST"))
            .json(&params)
            .send()
    }

    pub fn delete(&self, uri: &str) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .delete(url)
            .headers(self.construct_headers("DELETE"))
            .send()
    }

    pub fn set_bearer_token(&mut self, token: &str) {
        // could simply have general prop setter method instead of seperate bearer and baseurl
        self.token = token.to_string();
    }

    pub fn set_base_url(&mut self, base_url: &str) {
        // TODO: this should not be necessary
        self.base_url = base_url.to_string();
    }

    fn construct_headers(&self, method: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();

        if method == "POST" || method == "PUT" || method == "PATCH" {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }

        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(
                &std::env::var("USER_AGENT").unwrap_or(String::from(DEFAULT_API_USER_AGENT)),
            )
            .expect("user agent"),
        );

        if self.token != "" {
            let auth = format!("bearer {}", self.token);
            headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth).expect("token"));
        }

        headers
    }
}
