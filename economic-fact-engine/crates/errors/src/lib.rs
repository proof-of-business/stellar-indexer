use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Shared error enum for all off-chain corridor components.
///
/// **Privacy invariant**: No variant's `Display` output or serialized form
/// includes denomination, Note preimage fields, KYC credential content,
/// or any user identity data.
///
/// The `#[serde(tag = "code", content = "detail")]` annotation produces
/// structured JSON of the form `{"code": "ProofVerificationFailed"}` for
/// unit variants, enabling machine-readable error handling by integrators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "code", content = "detail")]
pub enum CorridorError {
    /// The submitted ZK proof did not satisfy the circuit constraints as
    /// verified by the on-chain verifier contract.
    #[error("proof verification failed")]
    ProofVerificationFailed,

    /// The nullifier submitted during a withdrawal has already been recorded
    /// in the shielded pool's spent-nullifier set (double-spend attempt).
    #[error("nullifier already spent")]
    NullifierAlreadySpent,

    /// A withdrawal was attempted for a Note that has already been redeemed
    /// (surfaced by the off-ramp after receiving `NullifierAlreadySpent` from the pool).
    #[error("note already redeemed")]
    NoteAlreadyRedeemed,

    /// The Soroban deposit transaction failed after the fiat deposit was confirmed
    /// by the on-ramp anchor; a refund to the sender's anchor account has been initiated.
    #[error("deposit atomicity failure")]
    DepositAtomicityFailure,

    /// A direct USDC transfer to the shielded pool was attempted without a
    /// valid Deposit_Circuit ZK proof.
    #[error("unshielded deposit rejected")]
    UnshieldedDepositRejected,

    /// The shielded pool's Merkle tree has reached maximum capacity (2^20 leaves).
    #[error("pool capacity exceeded")]
    PoolCapacityExceeded,

    /// The deposit or withdrawal amount is invalid (zero, negative, or out of range).
    #[error("invalid amount")]
    InvalidAmount,

    /// The KYC credential presented is malformed or its signature does not
    /// verify under the Compliance Oracle's public key.
    #[error("invalid credential")]
    InvalidCredential,

    /// The KYC credential's expiry timestamp has passed at the time of proof
    /// generation; the holder must obtain a renewed credential.
    #[error("credential expired")]
    CredentialExpired,

    /// The off-ramp anchor failed to confirm MXN disbursement within the
    /// 24-hour settlement window; manual reconciliation is required.
    #[error("off-ramp settlement timeout")]
    OfframpSettlementTimeout,

    /// An error occurred while communicating with the on-ramp or off-ramp
    /// SEP-24 anchor service.
    #[error("anchor integration failure")]
    AnchorIntegrationFailure,
}
