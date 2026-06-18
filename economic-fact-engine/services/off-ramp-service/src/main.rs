use axum::{routing::post, Router};

#[tokio::main]
async fn main() {
    let app = Router::new().route("/payout", post(handle_payout));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3002").await.unwrap();
    println!("off-ramp-service listening on :3002");
    axum::serve(listener, app).await.unwrap();
}

async fn handle_payout() -> &'static str {
    // TODO: verify ZK proof and disburse funds to recipient.
    "ok"
}
