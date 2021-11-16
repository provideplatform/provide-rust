use http;
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

#[derive(Debug)]
pub struct AdditionalHeader {
    pub key: &'static str,
    pub value: http::HeaderValue,
}
