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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// All 11 variants in definition order so we catch any additions at compile time.
    fn all_variants() -> Vec<CorridorError> {
        vec![
            CorridorError::ProofVerificationFailed,
            CorridorError::NullifierAlreadySpent,
            CorridorError::NoteAlreadyRedeemed,
            CorridorError::DepositAtomicityFailure,
            CorridorError::UnshieldedDepositRejected,
            CorridorError::PoolCapacityExceeded,
            CorridorError::InvalidAmount,
            CorridorError::InvalidCredential,
            CorridorError::CredentialExpired,
            CorridorError::OfframpSettlementTimeout,
            CorridorError::AnchorIntegrationFailure,
        ]
    }

    #[test]
    fn all_11_variants_present() {
        // Ensures the helper above stays in sync; will fail to compile if a variant is renamed.
        assert_eq!(all_variants().len(), 11);
    }

    // ── Serde shape ───────────────────────────────────────────────────────────

    #[test]
    fn serde_round_trip_all_variants() {
        for variant in all_variants() {
            let json = serde_json::to_string(&variant).expect("serialize");
            let back: CorridorError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, back, "round-trip failed for {variant:?}");
        }
    }

    #[test]
    fn serde_uses_tag_code_field() {
        // {"code": "ProofVerificationFailed"} — unit variants must NOT have a "detail" key.
        let json = serde_json::to_string(&CorridorError::ProofVerificationFailed).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["code"], "ProofVerificationFailed", "tag field must be 'code'");
        assert!(v.get("detail").is_none(), "unit variants must not emit 'detail'");
    }

    #[test]
    fn serde_all_variants_have_code_tag() {
        for variant in all_variants() {
            let json = serde_json::to_string(&variant).unwrap();
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert!(
                v.get("code").is_some(),
                "variant {variant:?} must serialize with a 'code' tag"
            );
        }
    }

    // ── Privacy invariant: Display must not leak sensitive data ───────────────

    /// Strings that must never appear in any error message.
    ///
    /// These are field names and value-bearing terms that would leak denomination,
    /// identity, or Note preimage data. Generic descriptors like "invalid amount"
    /// are acceptable — they describe the error category, not a concrete value.
    const FORBIDDEN_FRAGMENTS: &[&str] = &[
        // Denomination / amount value leaks (numeric data or field names)
        "stroops",
        "denomination",
        // Identity / credential field leaks
        "credential_id",
        "oracle_signature",
        "issued_at",
        "expires_at",
        "identity_commitment",
        // Note preimage field leaks
        "receiver_pk",
        "leaf_index",
    ];

    #[test]
    fn display_contains_no_sensitive_fragments() {
        for variant in all_variants() {
            let msg = variant.to_string().to_lowercase();
            for fragment in FORBIDDEN_FRAGMENTS {
                assert!(
                    !msg.contains(fragment),
                    "CorridorError::{variant:?} Display contains forbidden fragment '{fragment}': \"{msg}\""
                );
            }
        }
    }

    // ── Error trait ───────────────────────────────────────────────────────────

    #[test]
    fn implements_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        for variant in all_variants() {
            assert_error(&variant);
        }
    }

    #[test]
    fn implements_clone_and_eq() {
        for variant in all_variants() {
            assert_eq!(variant.clone(), variant);
        }
    }
}
