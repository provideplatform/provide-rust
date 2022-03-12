pub use crate::models::client::{ApiClient, Params, Response};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
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
        params: Params,
        additional_headers: Option<Vec<(String, String)>>,
        query_params: Option<Vec<(String, String)>>,
    ) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .get(url)
            .headers(self.construct_headers(additional_headers.unwrap_or(vec![]), "GET"))
            .query(&query_params.unwrap_or(vec![]))
            .json(&params)
            .send()
    }

    pub fn patch(
        &self,
        uri: &str,
        params: Params,
        additional_headers: Option<Vec<(String, String)>>,
    ) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .patch(url)
            .headers(self.construct_headers(additional_headers.unwrap_or(vec![]), "PATCH"))
            .json(&params)
            .send()
    }

    pub fn put(
        &self,
        uri: &str,
        params: Params,
        additional_headers: Option<Vec<(String, String)>>,
    ) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .put(url)
            .headers(self.construct_headers(additional_headers.unwrap_or(vec![]), "PUT"))
            .json(&params)
            .send()
    }

    pub fn post(
        &self,
        uri: &str,
        params: Params,
        additional_headers: Option<Vec<(String, String)>>,
    ) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .post(url)
            .headers(self.construct_headers(additional_headers.unwrap_or(vec![]), "POST"))
            .json(&params)
            .send()
    }

    pub fn delete(
        &self,
        uri: &str,
        params: Params,
        additional_headers: Option<Vec<(String, String)>>,
    ) -> impl std::future::Future<Output = Response> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .delete(url)
            .headers(self.construct_headers(additional_headers.unwrap_or(vec![]), "DELETE"))
            .json(&params)
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

    fn construct_headers(
        &self,
        additional_headers: Vec<(String, String)>,
        method: &str,
    ) -> HeaderMap {
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

        for (key, value) in additional_headers {
            let header_name = HeaderName::from_bytes(key.as_bytes()).expect("header name");
            let header_value = HeaderValue::from_str(&value).expect("header value");
            headers.insert(header_name, header_value);
        }

        headers
    }
}

// TODO-- GET pagination capabilities
