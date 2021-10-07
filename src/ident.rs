pub use crate::client::ApiClient;

pub struct Ident {
    pub client: ApiClient
}

impl Ident {
    pub fn init(scheme: Option<String>, host: Option<String>, token: Option<String>) -> Result<Self, ()> {
        let _scheme = scheme.unwrap_or(String::from("https"));
        let _host = host.unwrap_or(String::from("ident.provide.services"));

        let client = ApiClient::init(Some(_scheme), Some(_host), Some(String::from("api/v1")), token).expect("ident api client");
        Ok( Self { client })
    }

    // applications
    pub async fn create_application(&self, params: serde_json::Value) -> Result<reqwest::Response, reqwest::Error> {
        let res = self.client.post(String::from("applications"), params).await?;
        Ok( res )
    }

    pub async fn applications(&self, params: serde_json::Value) -> Result<reqwest::Response, reqwest::Error> {
        let res = self.client.get(String::from("applications"), params).await?;
        Ok( res )
    }
    
    pub fn associate_user_with_application() {}

    pub async fn application(&self, application_id: String, params: serde_json::Value) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}", application_id);
        let res = self.client.get(uri, params).await?;
        Ok( res )
    }

    pub fn application_users() {}

    pub async fn update_application(&self, application_id: String, params: serde_json::Value) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("applications/{}", application_id);
        let res = self.client.put(uri, params).await?;
        Ok( res )
    }

    pub fn delete_application() {}

    // organizations
    pub fn organizations() {}

    pub fn create_organization() {}

    pub fn organization() {}

    pub fn update_organization() {}

    // tokens
    pub fn tokens() {}

    pub fn revoke_token() {}

    pub fn authorize_long_term_token() {}

    pub async fn authenticate(&self, params: serde_json::Value) -> Result<reqwest::Response, reqwest::Error> {
        let res = self.client.post(String::from("authenticate"), params).await?;
        Ok( res )
    }

    // users
    pub fn users() {}
    
    pub fn create_user() {}

    pub fn update_user() {}

    pub fn user() {}
    
    pub fn delete_user() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_client() {
        let ident = Ident::init(None, None, Some(String::from(""))).expect("ident client");

        assert_eq!(ident.client.base_url, String::from("https://ident.provide.services/api/v1"))
    }
}