use axum::{routing::post, Json, Router};
use types::ComplianceAttestation;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/attest", post(handle_attest));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3003").await.unwrap();
    println!("compliance-oracle listening on :3003");
    axum::serve(listener, app).await.unwrap();
}

async fn handle_attest() -> Json<ComplianceAttestation> {
    // TODO: perform AML/KYC checks and return signed attestation.
    Json(ComplianceAttestation {
        transfer_id: String::new(),
        approved: false,
        reason: Some("not implemented".into()),
    })
}
