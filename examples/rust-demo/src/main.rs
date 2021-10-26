use provide_rust::ident::{Ident, User};
use provide_rust::client::ApiClient;
use serde_json::json;

#[tokio::main]
async fn main() {
    // initialize ident client with empty access token
    let ident: ApiClient = Ident::factory("");

    // create user request body
    let create_user_params = json!({
        "first_name": "example",
        "last_name": "user",
        "email": "example.user@example.org",
        "password": "password123",
    });

    let create_user_res = ident.create_user(Some(create_user_params)).await.expect("create user response");

    // deserialize into Ident User struct
    let body = create_user_res.json::<User>().await.expect("create user body");
    println!("{:?}", body);
}
