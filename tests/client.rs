use provide_rust::api::client::ApiClient;

#[test]
fn new_api_client() {
    let scheme = "https";
    let host = "provide.services";
    let path = "api/";
    let token = "";

    let client = ApiClient::new(scheme, host, path, token);
    assert_eq!(client.base_url, "https://provide.services/api/")
}
// TODO: fix the use of 'pub use crate' vs 'use crate'
