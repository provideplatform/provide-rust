use async_trait::async_trait;

use crate::client::{ApiClient, Response, Params};
pub use crate::models::privacy::*;

const DEFAULT_SCHEME: &str = "https";
const DEFAULT_HOST: &str = "privacy.provide.services";
const DEFAULT_PATH: &str = "api/v1";

#[async_trait]
pub trait Privacy {
    fn factory(token: &str) -> Self;

    async fn list_circuits(&self) -> Response;

    async fn create_circuit(&self, params: Params) -> Response;

    async fn get_circuit(&self, circuit_id: &str) -> Response;

    async fn generate_proof(&self, circuit_id: &str, params: Params) -> Response;

    async fn verify_proof(&self, circuit_id: &str, params: Params) -> Response;

    async fn retrieve_store_value(&self, circuit_id: &str, leaf_index: &str) -> Response;
}

#[async_trait]
impl Privacy for ApiClient {
    fn factory(token: &str) -> Self {
        let scheme = std::env::var("PRIVACY_API_SCHEME").unwrap_or(String::from(DEFAULT_SCHEME));
        let host = std::env::var("PRIVACY_API_HOST").unwrap_or(String::from(DEFAULT_HOST));
        let path = std::env::var("PRIVACY_API_PATH").unwrap_or(String::from(DEFAULT_PATH));
    
        return ApiClient::new(&scheme, &host, &path, token);
    }

    async fn list_circuits(&self) -> Response {
        return self.get("circuits", None, None).await
    }

    async fn create_circuit(&self, params: Params) -> Response {
        return self.post("circuits", params, None).await
    }

    async fn get_circuit(&self, circuit_id: &str) -> Response {
        let uri = format!("circuits/{}", circuit_id);
        return self.get(&uri, None, None).await
    }

    async fn generate_proof(&self, circuit_id: &str, params: Params) -> Response {
        let uri = format!("circuits/{}/prove", circuit_id);
        return self.post(&uri, params, None).await
    }

    async fn verify_proof(&self, circuit_id: &str, params: Params) -> Response {
        let uri = format!("circuits/{}/verify", circuit_id);
        return self.post(&uri, params, None).await
    }

    async fn retrieve_store_value(&self, circuit_id: &str, leaf_index: &str) -> Response {
        let uri = format!("circuits/{}/notes/{}", circuit_id, leaf_index);
        return self.get(&uri, None, None).await
    }
}

// MAKE THESE APPLICATION SCOPED
#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::name::en::{Name, FirstName, LastName};
    use fake::faker::internet::en::{FreeEmail, Password};
    use fake::Fake;
    use crate::ident::{Ident, AuthenticateResponse, Application, Token};
    use serde_json::json;
    use tokio::time::{self, Duration};

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

    async fn deploy_circuit(privacy: &ApiClient) -> Circuit {
        let create_circuit_params = Some(json!({
            "name": Name().fake::<String>(),
            "identifier": "cubic",
            "provider": "gnark",
            "proving_scheme": "groth16",
            "curve": "BN254",
        }));
        
        let create_circuit_res = privacy.create_circuit(create_circuit_params).await.expect("create circuit response");
        assert_eq!(create_circuit_res.status(), 201);

        return create_circuit_res.json::<Circuit>().await.expect("create circuit body");
    }

    #[tokio::test]
    async fn list_circuits() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let privacy: ApiClient = Privacy::factory(&access_token);

        let list_circuits_res = privacy.list_circuits().await.expect("list circuits response");
        assert_eq!(list_circuits_res.status(), 200);
    }

    #[tokio::test]
    async fn create_circuit() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let privacy: ApiClient = Privacy::factory(&access_token);
        let _ = deploy_circuit(&privacy).await;
    }

    #[tokio::test]
    async fn get_circuit() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let privacy: ApiClient = Privacy::factory(&access_token);
        let deploy_circuit_body = deploy_circuit(&privacy).await;

        let get_circuit_res = privacy.get_circuit(&deploy_circuit_body.id).await.expect("get circuit response");
        assert_eq!(get_circuit_res.status(), 200);
    }

    #[tokio::test]
    async fn generate_proof() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let application_data = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": authentication_res_body.user.id,
            "name": format!("{} {}", Name().fake::<String>(), "Application"),
            "description": "Some application description",
            "type": "baseline",
            "hidden": false
        }));

        let create_application_res = ident.create_application(application_data).await.expect("generate application response");
        assert_eq!(create_application_res.status(), 201);

        let create_application_body = create_application_res.json::<Application>().await.expect("create application body");
        let application_auth_params = Some(json!({
            "application_id": create_application_body.id,
            "scope": "offline_access",
        }));

        let application_auth_res = ident.application_authorization(application_auth_params).await.expect("application authorization response");

        let application_auth_body = application_auth_res.json::<Token>().await.expect("application authorization body");
        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let privacy: ApiClient = Privacy::factory(&application_access_token);

        let deploy_circuit_body = deploy_circuit(&privacy).await;

        let mut interval = time::interval(Duration::from_millis(500));
        let mut circuit_status = match deploy_circuit_body.status {
            Some(string) => string,
            None => panic!("deploy circuit status not found"),
        };

        while circuit_status != "provisioned" {
            interval.tick().await;

            let get_circuit_res = privacy.get_circuit(&deploy_circuit_body.id).await.expect("get circuit response");
            assert_eq!(get_circuit_res.status(), 200);

            let get_circuit_body = get_circuit_res.json::<Circuit>().await.expect("get circuit body");
            circuit_status = match get_circuit_body.status {
                Some(string) => string,
                None => panic!("get circuit body status not found"),
            };
        }

        let generate_proof_param = Some(json!({
            "identifier": deploy_circuit_body.identifier,
            "proving_scheme": "groth16",
            "curve": "BN254",
            "provider": "gnark",
            "name": deploy_circuit_body.name,
            "store_id": deploy_circuit_body.note_store_id,
            "witness": {
                "X": "3",
                "Y": "35",
            }
        }));

        let generate_proof_res = privacy.generate_proof(&deploy_circuit_body.id, generate_proof_param).await.expect("generate proof response");
        assert_eq!(generate_proof_res.status(), 200);
    }

    #[tokio::test]
    async fn verify_proof() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let application_data = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": authentication_res_body.user.id,
            "name": format!("{} {}", Name().fake::<String>(), "Application"),
            "description": "Some application description",
            "type": "baseline",
            "hidden": false
        }));

        let create_application_res = ident.create_application(application_data).await.expect("generate application response");
        assert_eq!(create_application_res.status(), 201);

        let create_application_body = create_application_res.json::<Application>().await.expect("create application body");
        let application_auth_params = Some(json!({
            "application_id": create_application_body.id,
            "scope": "offline_access",
        }));

        let application_auth_res = ident.application_authorization(application_auth_params).await.expect("application authorization response");

        let application_auth_body = application_auth_res.json::<Token>().await.expect("application authorization body");
        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let privacy: ApiClient = Privacy::factory(&application_access_token);

        let deploy_circuit_body = deploy_circuit(&privacy).await;

        let mut interval = time::interval(Duration::from_millis(500));
        let mut circuit_status = match deploy_circuit_body.status {
            Some(string) => string,
            None => panic!("deploy circuit status not found"),
        };

        while circuit_status != "provisioned" {
            interval.tick().await;

            let get_circuit_res = privacy.get_circuit(&deploy_circuit_body.id).await.expect("get circuit response");
            assert_eq!(get_circuit_res.status(), 200);

            let get_circuit_body = get_circuit_res.json::<Circuit>().await.expect("get circuit body");
            circuit_status = match get_circuit_body.status {
                Some(string) => string,
                None => panic!("get circuit body status not found"),
            };
        }

        let generate_proof_param = Some(json!({
            "identifier": deploy_circuit_body.identifier,
            "proving_scheme": "groth16",
            "curve": "BN254",
            "provider": "gnark",
            "name": deploy_circuit_body.name,
            "store_id": deploy_circuit_body.note_store_id,
            "witness": {
                "X": "3",
                "Y": "35",
            },
        }));

        let generate_proof_res = privacy.generate_proof(&deploy_circuit_body.id, generate_proof_param).await.expect("generate proof response");
        assert_eq!(generate_proof_res.status(), 200);

        let create_proof_body = generate_proof_res.json::<Proof>().await.expect("create proof body");

        let verify_proof_params = Some(json!({
            "witness": {
                "X": "3",
                "Y": "35",
            },
            "proof": create_proof_body.proof,
        }));

        let verify_proof_res = privacy.verify_proof(&deploy_circuit_body.id, verify_proof_params).await.expect("verify proof response");
        assert_eq!(verify_proof_res.status(), 200);
    }

    #[tokio::test]
    async fn retrieve_store_value() {
        let authentication_res_body = generate_new_user_and_token().await;
        let access_token = match authentication_res_body.token.access_token {
            Some(string) => string,
            None => panic!("authentication response access token not found"),
        };

        let ident: ApiClient = Ident::factory(&access_token);

        let application_data = Some(json!({
            "network_id": ROPSTEN_NETWORK_ID,
            "user_id": authentication_res_body.user.id,
            "name": format!("{} {}", Name().fake::<String>(), "Application"),
            "description": "Some application description",
            "type": "baseline",
            "hidden": false
        }));

        let create_application_res = ident.create_application(application_data).await.expect("generate application response");
        assert_eq!(create_application_res.status(), 201);

        let create_application_body = create_application_res.json::<Application>().await.expect("create application body");
        let application_auth_params = Some(json!({
            "application_id": create_application_body.id,
            "scope": "offline_access",
        }));

        let application_auth_res = ident.application_authorization(application_auth_params).await.expect("application authorization response");

        let application_auth_body = application_auth_res.json::<Token>().await.expect("application authorization body");
        let application_access_token = match application_auth_body.access_token {
            Some(string) => string,
            None => panic!("application authentication response access token not found"),
        };

        let privacy: ApiClient = Privacy::factory(&application_access_token);

        let deploy_circuit_body = deploy_circuit(&privacy).await;

        let mut interval = time::interval(Duration::from_millis(500));
        let mut circuit_status = match deploy_circuit_body.status {
            Some(string) => string,
            None => panic!("deploy circuit status not found"),
        };

        while circuit_status != "provisioned" {
            interval.tick().await;

            let get_circuit_res = privacy.get_circuit(&deploy_circuit_body.id).await.expect("get circuit response");
            assert_eq!(get_circuit_res.status(), 200);

            let get_circuit_body = get_circuit_res.json::<Circuit>().await.expect("get circuit body");
            circuit_status = match get_circuit_body.status {
                Some(string) => string,
                None => panic!("get circuit body status not found"),
            };
        }

        let generate_proof_param = Some(json!({
            "identifier": deploy_circuit_body.identifier,
            "proving_scheme": "groth16",
            "curve": "BN254",
            "provider": "gnark",
            "name": deploy_circuit_body.name,
            "store_id": deploy_circuit_body.note_store_id,
            "witness": {
                "X": "3",
                "Y": "35",
            },
        }));

        let generate_proof_res = privacy.generate_proof(&deploy_circuit_body.id, generate_proof_param).await.expect("generate proof response");
        assert_eq!(generate_proof_res.status(), 200);

        let retrieve_store_value_res = privacy.retrieve_store_value(&deploy_circuit_body.id, "0").await.expect("retrieve store value response");
        assert_eq!(retrieve_store_value_res.status(), 200);
    }
}