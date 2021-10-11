use http;
use reqwest;
use serde_json;

// TODO: make properties private?
#[derive(Debug)]
pub struct ApiClient {
    pub client: reqwest::Client,
    pub base_url: String,
    pub token: String,
}

#[derive(Debug)]
pub struct AdditionalHeader {
    pub key: &'static str,
    pub value: http::HeaderValue
}

// const DEFAULT_API_SCHEME: &str = "https";
// const DEFAULT_API_HOST: &str = "provide.services";
const DEFAULT_API_USER_AGENT: &str = "provide-rust client library";
// const DEFAULT_API_MAX_ATTEMPTS: &i32 = &5;
// const DEFAULT_API_TIMEOUT: &i32 = &120;

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

    pub fn get(
        &self,
        uri: &str,
        params: &Option<serde_json::Value>,
        additional_headers: Option<Vec<AdditionalHeader>>
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .get(url)
            .headers(self.construct_headers(additional_headers))
            .json(&params)
            .send()
    }

    pub fn patch(
        &self,
        uri: &str,
        params: serde_json::Value,
        additional_headers: Option<Vec<AdditionalHeader>>
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .patch(url)
            .headers(self.construct_headers(additional_headers))
            .json(&params)
            .send()
    }

    pub fn put(
        &self,
        uri: &str,
        params: &Option<serde_json::Value>,
        additional_headers: Option<Vec<AdditionalHeader>>
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .put(url)
            .headers(self.construct_headers(additional_headers))
            .json(&params)
            .send()
    }

    pub fn post(
        &self,
        uri: &str,
        params: &Option<serde_json::Value>,
        additional_headers: Option<Vec<AdditionalHeader>>
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .post(url)
            .headers(self.construct_headers(additional_headers))
            .json(params)
            .send()
    }

    pub fn delete(
        &self,
        uri: &str,
        params: &Option<serde_json::Value>,
        additional_headers: Option<Vec<AdditionalHeader>>
    ) -> impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>> {
        let url = format!("{}/{}", self.base_url, uri);
        self.client
            .delete(url)
            .headers(self.construct_headers(additional_headers))
            .json(params)
            .send()
    }

    

    pub fn construct_headers(&self, additional_headers: Option<Vec<AdditionalHeader>>) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();

        // make conditional
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

        match additional_headers {
            Some(more_headers) => {
                for header in more_headers {
                    headers.insert(header.key, header.value);
                }
            },
            None => {}
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
        let host = String::from("provide.services");
        let path = String::from("api/");
        let token = String::from("");

        let client = ApiClient::new(scheme, host, path, token);
        assert_eq!(client.base_url, "https://provide.services/api/")
    }
}
