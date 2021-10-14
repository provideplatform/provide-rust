pub use crate::client::{ApiClient, AdditionalHeader};
use std::result::{Result};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use serde_json::{Value};

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "nchain.provide.services";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait NChain {
    fn factory(token: String) -> Self;

    async fn list_accounts(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_account(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_account(&self, account_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_connectors(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_connector(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_connector(&self, connector_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn delete_connector(&self, connector_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_contracts(&self) -> Result<reqwest::Response, reqwest::Error>;

    async fn create_contract(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;

    async fn get_contract(&self, contract_id: &str) -> Result<reqwest::Response, reqwest::Error>;

    async fn execute_contract(&self, contract_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error>;
}

#[async_trait]
impl NChain for ApiClient {
    fn factory(token: String) -> Self {
        let scheme = std::env::var("NCHAIN_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("NCHAIN_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("NCHAIN_API_PATH").unwrap_or(String::from(DEFAULT_PATH));
    
        return ApiClient::new(scheme, host, path, token);
    }

    async fn list_accounts(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("accounts", None, None).await
    }

    async fn create_account(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("accounts", params, None).await
    }

    async fn get_account(&self, account_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("accounts/{}", account_id);
        return self.get(&uri, None, None).await
    }

    async fn get_connectors(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("connectors", None, None).await
    }

    async fn create_connector(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("connectors", params, None).await
    }

    async fn get_connector(&self, connector_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("connectors/{}", connector_id);
        return self.get(&uri, None, None).await
    }

    async fn delete_connector(&self, connector_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("connectors/{}", connector_id);
        return self.delete(&uri, None, None).await
    }

    async fn get_contracts(&self) -> Result<reqwest::Response, reqwest::Error> {
        return self.get("contracts", None, None).await
    }

    async fn create_contract(&self, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        return self.post("contracts", params, None).await
    }

    async fn get_contract(&self, contract_id: &str) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("contracts/{}", contract_id);
        return self.get(&uri, None, None).await
    }

    async fn execute_contract(&self, contract_id: &str, params: Option<Value>) -> Result<reqwest::Response, reqwest::Error> {
        let uri = format!("contracts/{}/execute", contract_id);
        return self.post(&uri, params, None).await
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Account {
    id: String,
    created_at: String,
    network_id: String,
    user_id: String,
    vault_id: String,
    key_id: String,
    public_key: String,
    address: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Connector {
    id: String,
    created_at: String,
    application_id: String,
    network_id: String,
    organization_id: Option<String>,
    name: String,
    r#type: String,
    status: String,
    description: Option<String>,

}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ConnectorConfig {
    api_port: i64,
    api_url: String,
    container: String,
    provider_id: String,
    region: String,
    role: String,
    security: Option<ConfigSecurity>,
    target_id: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ConfigSecurity {
    egress: String,
    ingress: Value, // FIXME
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Contract {
    id: String,
    created_at: String,
    application_id: String,
    organization_id: Option<String>,
    network_id: String,
    contract_id: Option<String>,
    transaction_id: Option<String>,
    name: String,
    address: String,
    r#type: Option<String>,
    accessed_at: Option<String>,
    pubsub_prefix: String,
}

// #[derive(Serialize, Deserialize, Debug, Default, Clone)]
// pub struct SecurityIngress {
//     r"0.0.0.0/0": IngressParams,
// }

// #[derive(Serialize, Deserialize, Debug, Default, Clone)]
// pub struct IngressParams {
//     tcp: Vec<i64>,
//     udp: Vec<i64>,
// }

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::name::en::{Name, FirstName, LastName};
    use fake::faker::internet::en::{FreeEmail, Password};
    use fake::{Fake};
    use crate::ident::{Ident, AuthenticateResponse, Application, Token};
    use serde_json::json;
    use tokio::time::{self, Duration};

    const ROPSTEN_NETWORK_ID: &str = "66d44f30-9092-4182-a3c4-bc02736d6ae5";

    async fn generate_new_user_and_token() -> AuthenticateResponse {
        let ident: ApiClient = Ident::factory("".to_string());

        let email = FreeEmail().fake::<String>();
        let password = Password(8..15).fake::<String>();

        let user_data = Some(json!({
            "first_name": FirstName().fake::<String>(),
            "last_name": LastName().fake::<String>(),
            "email": &email,
            "password": &password,
        }));
        let create_user_res = ident.create_user(user_data).await.expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let params = Some(json!({
            "email": &email,
            "password": &password,
            "scope": "offline_access",
        }));
        let authenticate_res = ident.authenticate(params).await.expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);

        return authenticate_res.json::<AuthenticateResponse>().await.expect("authentication response body");
    }

    async fn generate_new_application(ident: &ApiClient, user_id: &str) -> Application {
        let application_data = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": user_id,
            "name": format!("{} {}", Name().fake::<String>(), "Application"),
            "description": "Some application description",
            "type": "baseline",
            "hidden": false
        }));

        let create_application_res = ident.create_application(application_data).await.expect("generate application response");
        assert_eq!(create_application_res.status(), 201);

        return create_application_res.json::<Application>().await.expect("create application body")
    }

    async fn generate_application_auth(ident: &ApiClient, application_id: &str) -> Token {
        let application_authorization_params = Some(json!({
            "application_id": application_id,
            "scope": "offline_access",
        }));

        let application_auth_res = ident.application_authorization(application_authorization_params).await.expect("application authorization response");
        assert_eq!(application_auth_res.status(), 201);

        return application_auth_res.json::<Token>().await.expect("application authorization body")
    }

    #[tokio::test]
    async fn list_accounts() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(access_token);

        let get_accounts_res = nchain.list_accounts().await.expect("list accounts response");
        assert_eq!(get_accounts_res.status(), 200);
    }

    #[tokio::test]
    async fn create_account() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(access_token);

        let create_account_params = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
        }));

        let create_account_res = nchain.create_account(create_account_params).await.expect("create account response");
        assert_eq!(create_account_res.status(), 201);
    }

    #[tokio::test]
    async fn get_account() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(access_token);

        let create_account_params = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
        }));

        let create_account_res = nchain.create_account(create_account_params).await.expect("create account response");
        assert_eq!(create_account_res.status(), 201);

        let create_account_body = create_account_res.json::<Account>().await.expect("create account body");

        let get_account_res = nchain.get_account(&create_account_body.id).await.expect("get account response");
        assert_eq!(get_account_res.status(), 200);
    }

    #[tokio::test]
    async fn get_connectors() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body = generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(application_access_token);

        let get_connectors_res = nchain.get_connectors().await.expect("get connectors response");
        assert_eq!(get_connectors_res.status(), 200);
    }

    #[tokio::test]
    async fn create_connector() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body = generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(application_access_token);

        let create_connector_params = Some(json!({
            "application_id": create_application_body.id,
            "network_id": ROPSTEN_NETWORK_ID,
            "name": format!("{} {}", Name().fake::<String>(), "Connector"),
            "type": "provide",
            "config": {
                "api_port": 8080,
                "api_url": "https://ceeb3bca-3b92-44b9-8ac5-fdd4564-717022042.us-east-2.elb.amazonaws.com:8080",
                "container": "providenetwork-ipfs",
                "image": "provide/ident",
                "provider_id": "docker",
                "region": "us-east-2",
                "role": "peer",
                "target_id": "aws"
            },
        }));

        let create_connector_res = nchain.create_connector(create_connector_params).await.expect("create connector response");
        assert_eq!(create_connector_res.status(), 201);
    }

    #[tokio::test]
    async fn get_connector() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body = generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(application_access_token);

        let create_connector_params = Some(json!({
            "application_id": create_application_body.id,
            "network_id": ROPSTEN_NETWORK_ID,
            "name": format!("{} {}", Name().fake::<String>(), "Connector"),
            "type": "provide",
            "config": {
                "api_port": 8080,
                "api_url": "https://ceeb3bca-3b92-44b9-8ac5-fdd4564-717022042.us-east-2.elb.amazonaws.com:8080",
                "container": "providenetwork-ipfs",
                "image": "provide/ident",
                "provider_id": "docker",
                "region": "us-east-2",
                "role": "peer",
                "target_id": "aws"
            },
        }));

        let create_connector_res = nchain.create_connector(create_connector_params).await.expect("create connector response");
        assert_eq!(create_connector_res.status(), 201);

        let create_connector_body = create_connector_res.json::<Connector>().await.expect("create connector body");

        let get_connector_res = nchain.get_connector(&create_connector_body.id).await.expect("get connector response");
        assert_eq!(get_connector_res.status(), 200);
    }

    #[tokio::test]
    async fn delete_connector() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body = generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(application_access_token);

        let create_connector_params = Some(json!({
            "application_id": create_application_body.id,
            "network_id": ROPSTEN_NETWORK_ID,
            "name": format!("{} {}", Name().fake::<String>(), "Connector"),
            "type": "provide",
            "config": {
                "api_port": 8080,
                "api_url": "https://ceeb3bca-3b92-44b9-8ac5-fdd4564-717022042.us-east-2.elb.amazonaws.com:8080",
                "container": "providenetwork-ipfs",
                "image": "provide/ident",
                "provider_id": "docker",
                "region": "us-east-2",
                "role": "peer",
                "target_id": "aws"
            },
        }));

        let create_connector_res = nchain.create_connector(create_connector_params).await.expect("create connector response");
        assert_eq!(create_connector_res.status(), 201);

        let create_connector_body = create_connector_res.json::<Connector>().await.expect("create connector body");

        let delete_connector_res = nchain.delete_connector(&create_connector_body.id).await.expect("delete connector res");
        assert_eq!(delete_connector_res.status(), 500); // FIXME
    }

    #[tokio::test]
    async fn list_contracts() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body = generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(application_access_token);

        let get_contracts_res = nchain.get_contracts().await.expect("get contracts response");
        assert_eq!(get_contracts_res.status(), 200);
    }

    #[tokio::test]
    async fn create_contract() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body = generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(application_access_token);

        let create_contract_params = Some(json!({
            "application_id": &create_application_body.id,
            "network_id": ROPSTEN_NETWORK_ID,
            "name": format!("{} {}", Name().fake::<String>(), "Contract"),
            "address": "0x"
        }));

        let create_contract_res = nchain.create_contract(create_contract_params).await.expect("create contract response");
        assert_eq!(create_contract_res.status(), 201);
    }

    #[tokio::test]
    async fn get_contract() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(access_token);

        let create_application_body = generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body = generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(application_access_token);

        let create_contract_params = Some(json!({
            "application_id": &create_application_body.id,
            "network_id": ROPSTEN_NETWORK_ID,
            "name": format!("{} {}", Name().fake::<String>(), "Contract"),
            "address": "0x"
        }));

        let create_contract_res = nchain.create_contract(create_contract_params).await.expect("create contract response");
        assert_eq!(create_contract_res.status(), 201);

        let create_contract_body = create_contract_res.json::<Contract>().await.expect("create contract body");

        let get_contract_res = nchain.get_contract(&create_contract_body.id).await.expect("get contract response");
        assert_eq!(get_contract_res.status(), 200);
    }

    // #[tokio::test]
    // async fn execute_contract() {}
}

// ONLY USE GET IN PLACE OF RETRIEVE, LIST, etc
// change all as_str() to &
// for structs with org and app id they should both prolly be option