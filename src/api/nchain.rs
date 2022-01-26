use async_trait::async_trait;

use crate::api::client::{ApiClient, Params, Response};
pub use crate::models::nchain::*;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "nchain.provide.services";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait NChain {
    fn factory(token: &str) -> Self;

    async fn list_accounts(&self) -> Response;

    async fn create_account(&self, params: Params) -> Response;

    async fn get_account(&self, account_id: &str) -> Response;

    async fn get_connectors(&self) -> Response;

    async fn create_connector(&self, params: Params) -> Response;

    async fn get_connector(&self, connector_id: &str) -> Response;

    async fn delete_connector(&self, connector_id: &str) -> Response;

    async fn get_contracts(&self) -> Response;

    async fn create_contract(&self, params: Params) -> Response;

    async fn get_contract(&self, contract_id: &str) -> Response;

    async fn execute_contract(&self, contract_id: &str, params: Params) -> Response;

    async fn get_wallets(&self) -> Response;

    async fn create_wallet(&self, params: Params) -> Response;

    async fn get_wallet_accounts(&self, wallet_id: &str) -> Response;

    async fn get_networks(&self) -> Response;

    async fn create_network(&self, params: Params) -> Response;

    async fn update_network(&self, network_id: &str, params: Params) -> Response;

    async fn get_network(&self, network_id: &str) -> Response;

    async fn get_oracles(&self) -> Response;

    async fn create_oracle(&self, params: Params) -> Response;

    async fn get_oracle(&self, oracle_id: &str) -> Response;

    async fn update_oracle(&self, oracle_id: &str, params: Params) -> Response;

    async fn delete_oracle(&self, oracle_id: &str) -> Response;

    async fn get_transactions(&self) -> Response;

    async fn create_transaction(&self, params: Params) -> Response;

    async fn get_transaction(&self, tx_id: &str) -> Response;
}

#[async_trait]
impl NChain for ApiClient {
    fn factory(token: &str) -> Self {
        let scheme = std::env::var("NCHAIN_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("NCHAIN_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("NCHAIN_API_PATH").unwrap_or(String::from(DEFAULT_PATH));

        return ApiClient::new(&scheme, &host, &path, token);
    }

    async fn list_accounts(&self) -> Response {
        return self.get("accounts", None, None, None).await;
    }

    async fn create_account(&self, params: Params) -> Response {
        return self.post("accounts", params, None).await;
    }

    async fn get_account(&self, account_id: &str) -> Response {
        let uri = format!("accounts/{}", account_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn get_connectors(&self) -> Response {
        return self.get("connectors", None, None, None).await;
    }

    async fn create_connector(&self, params: Params) -> Response {
        return self.post("connectors", params, None).await;
    }

    async fn get_connector(&self, connector_id: &str) -> Response {
        let uri = format!("connectors/{}", connector_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn delete_connector(&self, connector_id: &str) -> Response {
        let uri = format!("connectors/{}", connector_id);
        return self.delete(&uri, None, None).await;
    }

    async fn get_contracts(&self) -> Response {
        return self.get("contracts", None, None, None).await;
    }

    async fn create_contract(&self, params: Params) -> Response {
        return self.post("contracts", params, None).await;
    }

    async fn get_contract(&self, contract_id: &str) -> Response {
        let uri = format!("contracts/{}", contract_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn execute_contract(&self, contract_id: &str, params: Params) -> Response {
        let uri = format!("contracts/{}/execute", contract_id);
        return self.post(&uri, params, None).await;
    }

    async fn get_wallets(&self) -> Response {
        return self.get("wallets", None, None, None).await;
    }

    async fn create_wallet(&self, params: Params) -> Response {
        return self.post("wallets", params, None).await;
    }

    async fn get_wallet_accounts(&self, wallet_id: &str) -> Response {
        let uri = format!("wallets/{}/accounts", wallet_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn get_networks(&self) -> Response {
        return self.get("networks", None, None, None).await;
    }

    async fn create_network(&self, params: Params) -> Response {
        return self.post("networks", params, None).await;
    }

    async fn update_network(&self, network_id: &str, params: Params) -> Response {
        let uri = format!("networks/{}", network_id);
        return self.put(&uri, params, None).await;
    }

    async fn get_network(&self, network_id: &str) -> Response {
        let uri = format!("networks/{}", network_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn get_oracles(&self) -> Response {
        return self.get("oracles", None, None, None).await;
    }

    async fn create_oracle(&self, params: Params) -> Response {
        return self.post("oracles", params, None).await;
    }

    async fn get_oracle(&self, oracle_id: &str) -> Response {
        let uri = format!("oracles/{}", oracle_id);
        return self.get(&uri, None, None, None).await;
    }

    async fn update_oracle(&self, oracle_id: &str, params: Params) -> Response {
        let uri = format!("oracles/{}", oracle_id);
        return self.put(&uri, params, None).await;
    }

    async fn delete_oracle(&self, oracle_id: &str) -> Response {
        let uri = format!("oracles/{}", oracle_id);
        return self.delete(&uri, None, None).await;
    }

    async fn get_transactions(&self) -> Response {
        return self.get("transactions", None, None, None).await;
    }

    async fn create_transaction(&self, params: Params) -> Response {
        return self.post("transactions", params, None).await;
    }

    async fn get_transaction(&self, tx_id: &str) -> Response {
        let uri = format!("transactions/{}", tx_id);
        return self.get(&uri, None, None, None).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ident::{Application, AuthenticateResponse, Ident, Token};
    use fake::faker::internet::en::{FreeEmail, Password};
    use fake::faker::name::en::{FirstName, LastName, Name};
    use fake::Fake;
    use serde_json::{json, Value};

    const ROPSTEN_NETWORK_ID: &str = "66d44f30-9092-4182-a3c4-bc02736d6ae5";

    async fn generate_new_user_and_token() -> AuthenticateResponse {
        let ident: ApiClient = Ident::factory("");

        let email = FreeEmail().fake::<String>();
        let password = Password(8..15).fake::<String>();

        let user_data = Some(json!({
            "first_name": FirstName().fake::<String>(),
            "last_name": LastName().fake::<String>(),
            "email": &email,
            "password": &password,
        }));
        let create_user_res = ident
            .create_user(user_data)
            .await
            .expect("create user response");
        assert_eq!(create_user_res.status(), 201);

        let params = Some(json!({
            "email": &email,
            "password": &password,
            "scope": "offline_access",
        }));
        let authenticate_res = ident
            .authenticate(params)
            .await
            .expect("authenticate response");
        assert_eq!(authenticate_res.status(), 201);

        return authenticate_res
            .json::<AuthenticateResponse>()
            .await
            .expect("authentication response body");
    }

    async fn generate_new_application(ident: &ApiClient, user_id: &str) -> Application {
        let application_data = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": user_id,
            "name": format!("{} Application", Name().fake::<String>()),
            "description": "Some application description",
            "type": "baseline",
            "hidden": false
        }));

        let create_application_res = ident
            .create_application(application_data)
            .await
            .expect("generate application response");
        assert_eq!(create_application_res.status(), 201);

        return create_application_res
            .json::<Application>()
            .await
            .expect("create application body");
    }

    async fn generate_application_auth(ident: &ApiClient, application_id: &str) -> Token {
        let application_authorization_params = Some(json!({
            "application_id": application_id,
            "scope": "offline_access",
        }));

        let application_auth_res = ident
            .application_authorization(application_authorization_params)
            .await
            .expect("application authorization response");
        assert_eq!(application_auth_res.status(), 201);

        return application_auth_res
            .json::<Token>()
            .await
            .expect("application authorization body");
    }

    #[tokio::test]
    async fn list_accounts() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let get_accounts_res = nchain
            .list_accounts()
            .await
            .expect("list accounts response");
        assert_eq!(
            get_accounts_res.status(),
            200,
            "get accounts response body {:?}",
            get_accounts_res.json::<Value>().await.unwrap()
        );
    }

    #[tokio::test]
    async fn create_account() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let create_account_params = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
        }));

        let create_account_res = nchain
            .create_account(create_account_params)
            .await
            .expect("create account response");
        assert_eq!(
            create_account_res.status(),
            201,
            "create account response body {:?}",
            create_account_res.json::<Value>().await.unwrap()
        );
    }

    #[tokio::test]
    async fn get_account() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let create_account_params = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
        }));

        let create_account_res = nchain
            .create_account(create_account_params)
            .await
            .expect("create account response");
        assert_eq!(create_account_res.status(), 201);

        let create_account_body = create_account_res
            .json::<Account>()
            .await
            .expect("create account body");

        let get_account_res = nchain
            .get_account(&create_account_body.id)
            .await
            .expect("get account response");
        assert_eq!(get_account_res.status(), 200);
    }

    #[tokio::test]
    async fn get_connectors() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body =
            generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&application_access_token);

        let get_connectors_res = nchain
            .get_connectors()
            .await
            .expect("get connectors response");
        assert_eq!(get_connectors_res.status(), 200);
    }

    #[tokio::test]
    async fn create_connector() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body =
            generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&application_access_token);

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

        let create_connector_res = nchain
            .create_connector(create_connector_params)
            .await
            .expect("create connector response");
        assert_eq!(create_connector_res.status(), 201);
    }

    #[tokio::test]
    async fn get_connector() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body =
            generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&application_access_token);

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

        let create_connector_res = nchain
            .create_connector(create_connector_params)
            .await
            .expect("create connector response");
        assert_eq!(create_connector_res.status(), 201);

        let create_connector_body = create_connector_res
            .json::<Connector>()
            .await
            .expect("create connector body");

        let get_connector_res = nchain
            .get_connector(&create_connector_body.id)
            .await
            .expect("get connector response");
        assert_eq!(get_connector_res.status(), 200);
    }

    #[tokio::test]
    async fn delete_connector() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body =
            generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&application_access_token);

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

        let create_connector_res = nchain
            .create_connector(create_connector_params)
            .await
            .expect("create connector response");
        assert_eq!(create_connector_res.status(), 201);

        let create_connector_body = create_connector_res
            .json::<Connector>()
            .await
            .expect("create connector body");

        let delete_connector_res = nchain
            .delete_connector(&create_connector_body.id)
            .await
            .expect("delete connector res");
        assert_eq!(delete_connector_res.status(), 500); // FIXME
    }

    #[tokio::test]
    async fn list_contracts() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body =
            generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&application_access_token);

        let get_contracts_res = nchain
            .get_contracts()
            .await
            .expect("get contracts response");
        assert_eq!(get_contracts_res.status(), 200);
    }

    #[tokio::test]
    async fn create_contract() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body =
            generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&application_access_token);

        let create_contract_params = Some(json!({
            "application_id": &create_application_body.id,
            "network_id": ROPSTEN_NETWORK_ID,
            "name": format!("{} {}", Name().fake::<String>(), "Contract"),
            "address": "0x"
        }));

        let create_contract_res = nchain
            .create_contract(create_contract_params)
            .await
            .expect("create contract response");
        assert_eq!(create_contract_res.status(), 201);
    }

    #[tokio::test]
    async fn get_contract() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body =
            generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&application_access_token);

        let create_contract_params = Some(json!({
            "application_id": &create_application_body.id,
            "network_id": ROPSTEN_NETWORK_ID,
            "name": format!("{} {}", Name().fake::<String>(), "Contract"),
            "address": "0x"
        }));

        let create_contract_res = nchain
            .create_contract(create_contract_params)
            .await
            .expect("create contract response");
        assert_eq!(create_contract_res.status(), 201);

        let create_contract_body = create_contract_res
            .json::<Contract>()
            .await
            .expect("create contract body");

        let get_contract_res = nchain
            .get_contract(&create_contract_body.id)
            .await
            .expect("get contract response");
        assert_eq!(get_contract_res.status(), 200);
    }

    #[tokio::test]
    async fn execute_contract() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body =
            generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&application_access_token);

        let create_contract_params = Some(json!({
            "application_id": &create_application_body.id,
            "network_id": ROPSTEN_NETWORK_ID,
            "name": format!("{} {}", Name().fake::<String>(), "Contract"),
            "address": "0x"
        }));

        let create_contract_res = nchain
            .create_contract(create_contract_params)
            .await
            .expect("create contract response");
        assert_eq!(create_contract_res.status(), 201);

        let create_contract_body = create_contract_res
            .json::<Contract>()
            .await
            .expect("create contract body");

        let create_wallet_params = Some(json!({
            "application_id": &create_application_body.id,
        }));

        let create_wallet_res = nchain
            .create_wallet(create_wallet_params)
            .await
            .expect("create wallet response");
        assert_eq!(create_wallet_res.status(), 201);

        let create_wallet_body = create_wallet_res
            .json::<Wallet>()
            .await
            .expect("create wallet body");

        let execute_contract_params = Some(json!({
            "value": 0,
            "wallet_id": create_wallet_body.id,
        }));

        let execute_contract_res = nchain
            .execute_contract(&create_contract_body.id, execute_contract_params)
            .await
            .expect("execute contract response");
        assert_eq!(execute_contract_res.status(), 202);
    }

    #[tokio::test]
    async fn get_wallets() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let get_wallets_res = nchain.get_wallets().await.expect("get wallets response");
        assert_eq!(get_wallets_res.status(), 200);
    }

    #[tokio::test]
    async fn create_wallet() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let create_wallet_params = Some(json!({
            "user_id": authentication_res_body.user.id,
        }));

        let create_wallet_res = nchain
            .create_wallet(create_wallet_params)
            .await
            .expect("create wallet response");
        assert_eq!(create_wallet_res.status(), 201);
    }

    #[tokio::test]
    async fn get_wallet_accounts() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let create_wallet_params = Some(json!({
            "user_id": authentication_res_body.user.id,
        }));

        let create_wallet_res = nchain
            .create_wallet(create_wallet_params)
            .await
            .expect("create wallet response");
        assert_eq!(create_wallet_res.status(), 201);

        let create_wallet_body = create_wallet_res
            .json::<Wallet>()
            .await
            .expect("create wallet body");

        let get_wallet_accounts_res = nchain
            .get_wallet_accounts(&create_wallet_body.id)
            .await
            .expect("get wallet accounts response");
        assert_eq!(get_wallet_accounts_res.status(), 200);
    }

    #[tokio::test]
    async fn get_networks() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let get_networks_res = nchain.get_networks().await.expect("get networks response");
        assert_eq!(get_networks_res.status(), 200);
    }

    #[tokio::test]
    async fn create_network() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let application_auth_body =
            generate_application_auth(&ident, &create_application_body.id).await;

        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&application_access_token);

        let create_network_params = Some(json!({
            "Application_id": &create_application_body.id,
            "name": format!("{} {}", Name().fake::<String>(), "Network"),
            "enabled": true,
            "chain_id": "0x1618585621",
            "config": {
                "chain": "test",
                "chainspec": {
                    "alloc": {},
                    "coinbase": 0,
                    "config": {
                        "byzantiumBlock": 0,
                        "constantinopleBlock": 0,
                        "eip150Block": 0,
                        "eip155Block": 0,
                        "eip158Block": 0,
                        "homesteadBlock": 0,
                        "petersburgBlock": 0
                    },
                    "difficulty": 131072,
                    "extraData": "",
                    "gasLimit": 3141592,
                    "mixhash": 0,
                    "nonce": 66,
                    "parentHash": 0,
                    "timestamp": 0
                },
                "engine_id": "ethash",
                "native_currency": "TEST",
                "network_id": 1618585621,
                "platform": "evm",
                "protocol_id": "pow"
            }
        }));

        let create_network_res = nchain
            .create_network(create_network_params)
            .await
            .expect("create network response");
        assert_eq!(create_network_res.status(), 201);
    }

    #[tokio::test]
    async fn update_network() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let nchain: ApiClient = NChain::factory(&access_token);

        let create_network_params = Some(json!({
            "application_id": &create_application_body.id,
            "name": format!("{} {}", Name().fake::<String>(), "Network"),
            "enabled": true,
            "chain_id": "0x1618585621",
            "config": {
                "chain": "test",
                "chainspec": {
                    "alloc": {},
                    "coinbase": 0,
                    "config": {
                        "byzantiumBlock": 0,
                        "constantinopleBlock": 0,
                        "eip150Block": 0,
                        "eip155Block": 0,
                        "eip158Block": 0,
                        "homesteadBlock": 0,
                        "petersburgBlock": 0
                    },
                    "difficulty": 131072,
                    "extraData": "",
                    "gasLimit": 3141592,
                    "mixhash": 0,
                    "nonce": 66,
                    "parentHash": 0,
                    "timestamp": 0
                },
                "engine_id": "ethash",
                "native_currency": "TEST",
                "network_id": 1618585621,
                "platform": "evm",
                "protocol_id": "pow"
            }
        }));

        let create_network_res = nchain
            .create_network(create_network_params)
            .await
            .expect("create network response");
        assert_eq!(create_network_res.status(), 201);

        let create_network_body = create_network_res
            .json::<Network>()
            .await
            .expect("create network body");

        let update_network_params = Some(json!({
            "description": "some network description"
        }));

        let update_network_res = nchain
            .update_network(&create_network_body.id, update_network_params)
            .await
            .expect("udpate network response");
        assert_eq!(update_network_res.status(), 204);
    }

    #[tokio::test]
    async fn get_network() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let create_application_body =
            generate_new_application(&ident, &authentication_res_body.user.id).await;

        let nchain: ApiClient = NChain::factory(&access_token);

        let create_network_params = Some(json!({
            "application_id": &create_application_body.id,
            "name": format!("{} {}", Name().fake::<String>(), "Network"),
            "enabled": true,
            "chain_id": "0x1618585621",
            "config": {
                "chain": "test",
                "chainspec": {
                    "alloc": {},
                    "coinbase": 0,
                    "config": {
                        "byzantiumBlock": 0,
                        "constantinopleBlock": 0,
                        "eip150Block": 0,
                        "eip155Block": 0,
                        "eip158Block": 0,
                        "homesteadBlock": 0,
                        "petersburgBlock": 0
                    },
                    "difficulty": 131072,
                    "extraData": "",
                    "gasLimit": 3141592,
                    "mixhash": 0,
                    "nonce": 66,
                    "parentHash": 0,
                    "timestamp": 0
                },
                "engine_id": "ethash",
                "native_currency": "TEST",
                "network_id": 1618585621,
                "platform": "evm",
                "protocol_id": "pow"
            }
        }));

        let create_network_res = nchain
            .create_network(create_network_params)
            .await
            .expect("create network response");
        assert_eq!(create_network_res.status(), 201);

        let create_network_body = create_network_res
            .json::<Network>()
            .await
            .expect("create network body");

        let get_network_res = nchain
            .get_network(&create_network_body.id)
            .await
            .expect("get network response");
        assert_eq!(get_network_res.status(), 200);
    }

    // #[tokio::test]
    // async fn get_oracles() {
    //     let authentication_res_body = generate_new_user_and_token().await;
    //     let access_token = match authentication_res_body.token.access_token {
    //         Some(string) => string,
    //         None => panic!("authentication response access token not found"),
    //     };

    //     let nchain: ApiClient = NChain::factory(&access_token);

    //     let get_oracles_res = nchain.get_oracles().await.expect("get oracles response");
    //     assert_eq!(get_oracles_res.status(), 200);
    // }

    #[tokio::test]
    async fn get_transactions() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let get_transactions_res = nchain
            .get_transactions()
            .await
            .expect("get transactions response");
        assert_eq!(get_transactions_res.status(), 200);
    }

    #[tokio::test]
    async fn create_transaction() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let create_wallet_params = Some(json!({
            "user_id": authentication_res_body.user.id,
        }));

        let create_wallet_res = nchain
            .create_wallet(create_wallet_params)
            .await
            .expect("create wallet response");
        assert_eq!(create_wallet_res.status(), 201);

        let create_wallet_body = create_wallet_res
            .json::<Wallet>()
            .await
            .expect("create wallet body");

        let create_transaction_params = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": &authentication_res_body.user.id,
            "wallet_id": &create_wallet_body.id,
            "hd_derivation_path": "m/44'/60'/0'/0/0",
            "to": "7c8fe6f1-38c3-4da1-b4b7-7591c6d0ca7c",
            "value": 0
        }));

        let create_transaction_res = nchain
            .create_transaction(create_transaction_params)
            .await
            .expect("create transaction response");
        assert_eq!(create_transaction_res.status(), 201);
    }

    #[tokio::test]
    async fn get_transaction() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let nchain: ApiClient = NChain::factory(&access_token);

        let create_wallet_params = Some(json!({
            "user_id": authentication_res_body.user.id,
        }));

        let create_wallet_res = nchain
            .create_wallet(create_wallet_params)
            .await
            .expect("create wallet response");
        assert_eq!(create_wallet_res.status(), 201);

        let create_wallet_body = create_wallet_res
            .json::<Wallet>()
            .await
            .expect("create wallet body");

        let create_transaction_params = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": &authentication_res_body.user.id,
            "wallet_id": &create_wallet_body.id,
            "hd_derivation_path": "m/44'/60'/0'/0/0",
            "to": "7c8fe6f1-38c3-4da1-b4b7-7591c6d0ca7c",
            "value": 0
        }));

        let create_transaction_res = nchain
            .create_transaction(create_transaction_params)
            .await
            .expect("create transaction response");
        assert_eq!(create_transaction_res.status(), 201);

        let create_transaction_body = create_transaction_res
            .json::<Transaction>()
            .await
            .expect("create transaction body");

        let get_transaction_res = nchain
            .get_transaction(&create_transaction_body.id)
            .await
            .expect("get transaction response");
        assert_eq!(get_transaction_res.status(), 200);
    }
}

// ONLY USE GET IN PLACE OF RETRIEVE, LIST, etc
// for structs with org and app id they should both prolly be option
// could consider 'nicer' naming ie list_multiple, get_single_detail, more deploy
// load balancer details call?

// how to add the comments that show on hover in vscode ie in TS it is @param, @return in /** **/ block

// make them non optional
