use http;
use reqwest;
use serde_json;

// make properties private?
// #[derive(Default)]
pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
    token: String,
}

const DEFAULT_API_SCHEME: &str = "https";
const DEFAULT_API_HOST: &str = "provide.services";
const DEFAULT_API_USER_AGENT: &str = "provide-rust client library";
const DEFAULT_API_MAX_ATTEMPTS: &i32 = &5;
const DEFAULT_API_TIMEOUT: &i32 = &120;

impl ApiClient {
    pub fn new(scheme: String, host: String, path: String, token: String) -> Self {
        let client = reqwest::Client::new();
        let base_url = format!("{}://{}/{}", scheme, host, path);

        Self {
            client,
            base_url,
            token,
        }
    }

    // pub fn client_factory?

    pub fn get(
        &self,
        uri: &str,
        params: &Option<serde_json::Value>,
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .get(url)
            .headers(self.construct_headers())
            .json(&params)
            .send()
    }

    pub fn patch(
        &self,
        uri: &str,
        params: serde_json::Value,
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .patch(url)
            .headers(self.construct_headers())
            .json(&params)
            .send()
    }

    pub fn put(
        &self,
        uri: &str,
        params: &Option<serde_json::Value>,
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .put(url)
            .headers(self.construct_headers())
            .json(&params)
            .send()
    }

    pub fn post(
        &self,
        uri: &str,
        params: &Option<serde_json::Value>,
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .post(url)
            .headers(self.construct_headers())
            .json(params)
            .send()
    }

    pub fn delete(
        &self,
        uri: &str,
        params: &Option<serde_json::Value>,
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .delete(url)
            .headers(self.construct_headers())
            .json(&params)
            .send()
    }

    pub fn construct_headers(&self) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();

        headers.insert(
            "content-type",
            http::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            "user-agent",
            http::HeaderValue::from_str(
                &std::env::var("USER_AGENT").unwrap_or(String::from(DEFAULT_API_USER_AGENT)),
            )
            .expect("user agent"),
        );

        if self.token != String::from("") {
            let auth = format!("bearer {}", self.token);
            headers.insert(
                "authorization",
                http::HeaderValue::from_str(&auth).expect("token"),
            );
        }

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_client_init() {
        let scheme = String::from("https");
        let host = String::from("api.provide.services");
        let path = String::from("api/");
        let token = String::from("");

        let client = ApiClient::new(scheme, host, path, token);
        assert_eq!(client.base_url, "https://api.provide.services/api/")
    }
}
