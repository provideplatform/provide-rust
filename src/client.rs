use reqwest;
use http;
use serde_json;

// #[derive(Default)]
pub struct ApiClient {
    pub client: reqwest::Client,
    pub base_url: String,
    pub token: String
}

const DEFAULT_API_SCHEME: &str = "https";
const DEFAULT_API_HOST: &str = "api.provide.services";
const DEFAULT_API_USER_AGENT: &str = "provide-rust client library";
const DEFAULT_API_MAX_ATTEMPTS: &i32 = &5;
const DEFAULT_API_TIMEOUT: &i32 = &120;

impl ApiClient {
    pub fn init(scheme: Option<String>, host: Option<String>, path: Option<String>, token: Option<String>) -> Result<Self, ()> {
        let client = reqwest::Client::new();

        let _scheme = std::env::var("API_SCHEME").unwrap_or(String::from(DEFAULT_API_SCHEME));
        let _host = std::env::var("API_HOST").unwrap_or(String::from(DEFAULT_API_HOST));

        let base_url = format!("{}://{}/{}", scheme.unwrap_or(_scheme), host.unwrap_or(_host), path.unwrap_or(String::from("api/")));
        
        Ok( Self {
            client,
            base_url,
            token: token.unwrap_or(String::from(""))
        })
    }

    pub async fn get(&self, uri: String, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client.get(url).headers(self.construct_headers()).json(&params).send().await
    }

    pub async fn patch(&self, uri: String, params: serde_json::Value) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client.patch(url).headers(self.construct_headers()).json(&params).send().await
    }

    pub async fn put(&self, uri: String, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client.put(url).headers(self.construct_headers()).json(&params).send().await
    }

    pub async fn post(&self, uri: String, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client.post(url).headers(self.construct_headers()).json(&params).send().await
    }

    pub async fn delete(&self, uri: String, params: Option<serde_json::Value>) -> Result<reqwest::Response, reqwest::Error> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client.delete(url).headers(self.construct_headers()).json(&params).send().await
    }

    pub fn construct_headers(&self) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();

        headers.insert("content-type", http::HeaderValue::from_static("application/json"));
        headers.insert("user-agent", http::HeaderValue::from_str(&std::env::var("USER_AGENT").unwrap_or(String::from(DEFAULT_API_USER_AGENT))).expect("user agent"));

        if self.token != String::from("") {
            let auth = format!("bearer {}", self.token);
            headers.insert("authorization", http::HeaderValue::from_str(&auth).expect("token"));
        }

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_client_init() {
        let client = ApiClient::init(None, None, None, None).expect("api client");

        assert_eq!(client.base_url, "https://api.provide.services/api/")
    }
}
