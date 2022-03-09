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
