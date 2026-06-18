use axum::{routing::post, Json, Router};
use types::TransferRequest;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/transfer", post(handle_transfer));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    println!("on-ramp-service listening on :3001");
    axum::serve(listener, app).await.unwrap();
}

async fn handle_transfer(Json(_req): Json<TransferRequest>) -> &'static str {
    // TODO: validate, generate ZK proof, and forward to shielded pool.
    "ok"
}
