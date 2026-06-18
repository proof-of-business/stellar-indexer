pub use errors::CorridorError;
pub use types::{ComplianceAttestation, TransferRequest};

/// High-level client for the private remittance corridor.
pub struct CorridorClient {
    base_url: String,
    http: reqwest::Client,
}

impl CorridorClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Submit a transfer request to the on-ramp service.
    pub async fn submit_transfer(
        &self,
        req: &TransferRequest,
    ) -> Result<String, CorridorError> {
        let url = format!("{}/transfer", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|e| CorridorError::Network(e.to_string()))?;
        let transfer_id = resp
            .text()
            .await
            .map_err(|e| CorridorError::Network(e.to_string()))?;
        Ok(transfer_id)
    }
}
