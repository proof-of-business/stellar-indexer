use serde::{Deserialize, Serialize};
use serde_with::serde_as;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Maximum transfer amount (in stroops) that may pass AML checks without extra scrutiny.
/// Equals 999.99999999 XLM-equivalent; values at or above this threshold are blocked by the
/// compliance circuit.
pub const AML_THRESHOLD_STROOPS: i64 = 99_999_999_999;

/// USDC asset issuer on the Stellar public network.
pub const USDC_ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// USDC asset code.
pub const USDC_CODE: &str = "USDC";

/// Depth of the incremental Merkle commitment tree.
pub const TREE_DEPTH: usize = 20;

// ─── Core note type ───────────────────────────────────────────────────────────

/// A shielded remittance note.  All fields are private-circuit witnesses; no field
/// should ever appear in an on-chain event or transaction memo.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Note {
    /// Transfer amount in stroops.
    pub denomination: i64,
    /// Random 32-byte blinding factor.
    #[serde_as(as = "serde_with::Bytes")]
    pub salt: [u8; 32],
    /// Recipient's shielded public key.
    #[serde_as(as = "serde_with::Bytes")]
    pub receiver_pk: [u8; 32],
    /// Position in the Merkle tree; `None` before the deposit is confirmed on-chain.
    pub leaf_index: Option<u32>,
}

// ─── Commitment / Nullifier newtypes ──────────────────────────────────────────

/// SHA-256 commitment to a note's fields.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Commitment(#[serde_as(as = "serde_with::Bytes")] pub [u8; 32]);

/// Nullifier preventing double-spend; derived from salt and receiver_pk.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Nullifier(#[serde_as(as = "serde_with::Bytes")] pub [u8; 32]);

// ─── Proof & public inputs ────────────────────────────────────────────────────

/// Serialised Groth16 proof: π_a (48 B) ‖ π_b (96 B) ‖ π_c (48 B) = 192 bytes.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofBytes(#[serde_as(as = "serde_with::Bytes")] pub [u8; 192]);

/// Public inputs to a Groth16 circuit; each element is a BLS12-381 Fr scalar
/// serialised as a big-endian 32-byte array.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicInputs(pub Vec<[u8; 32]>);

// ─── Merkle path ──────────────────────────────────────────────────────────────

/// Witness for an incremental Merkle membership proof at depth 20.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerklePath {
    /// Sibling hashes at each level (index 0 = leaf level).
    #[serde_as(as = "[serde_with::Bytes; 20]")]
    pub siblings: [[u8; 32]; 20],
    /// Path direction at each level: `false` = left child, `true` = right child.
    pub indices: [bool; 20],
    /// Position of the leaf in the tree.
    pub leaf_index: u32,
}

// ─── KYC credential ───────────────────────────────────────────────────────────

/// KYC/AML credential issued by the compliance oracle.
/// The `identity_commitment` is a ZK commitment — no PII is stored here.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KycCredential {
    /// Unique credential identifier (UUID v4).
    pub credential_id: String,
    /// Unix timestamp (seconds) when the credential was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the credential expires.
    pub expires_at: u64,
    /// ZK commitment to the holder's identity (not the identity itself).
    #[serde_as(as = "serde_with::Bytes")]
    pub identity_commitment: [u8; 32],
    /// Ed25519 signature by the compliance oracle over the credential fields.
    #[serde_as(as = "serde_with::Bytes")]
    pub oracle_signature: [u8; 64],
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zero32() -> [u8; 32] {
        [0u8; 32]
    }

    fn zero64() -> [u8; 64] {
        [0u8; 64]
    }

    fn zero192() -> [u8; 192] {
        [0u8; 192]
    }

    #[test]
    fn constants_values() {
        assert_eq!(AML_THRESHOLD_STROOPS, 99_999_999_999_i64);
        assert_eq!(USDC_CODE, "USDC");
        assert_eq!(TREE_DEPTH, 20);
        assert!(!USDC_ISSUER.is_empty());
    }

    #[test]
    fn note_serde_round_trip() {
        let note = Note {
            denomination: 1_000_000,
            salt: zero32(),
            receiver_pk: zero32(),
            leaf_index: Some(7),
        };
        let json = serde_json::to_string(&note).unwrap();
        let back: Note = serde_json::from_str(&json).unwrap();
        assert_eq!(note, back);
    }

    #[test]
    fn commitment_serde_round_trip() {
        let c = Commitment(zero32());
        assert_eq!(c, serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap());
    }

    #[test]
    fn nullifier_serde_round_trip() {
        let n = Nullifier(zero32());
        assert_eq!(n, serde_json::from_str(&serde_json::to_string(&n).unwrap()).unwrap());
    }

    #[test]
    fn proof_bytes_serde_round_trip() {
        let p = ProofBytes(zero192());
        assert_eq!(p, serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap());
    }

    #[test]
    fn public_inputs_serde_round_trip() {
        let pi = PublicInputs(vec![zero32(), zero32()]);
        assert_eq!(pi, serde_json::from_str(&serde_json::to_string(&pi).unwrap()).unwrap());
    }

    #[test]
    fn merkle_path_serde_round_trip() {
        let mp = MerklePath {
            siblings: [[1u8; 32]; 20],
            indices: [true; 20],
            leaf_index: 42,
        };
        let json = serde_json::to_string(&mp).unwrap();
        let back: MerklePath = serde_json::from_str(&json).unwrap();
        assert_eq!(mp, back);
    }

    #[test]
    fn kyc_credential_serde_round_trip() {
        let cred = KycCredential {
            credential_id: "test-uuid".to_string(),
            issued_at: 1_000_000,
            expires_at: 2_000_000,
            identity_commitment: zero32(),
            oracle_signature: zero64(),
        };
        let json = serde_json::to_string(&cred).unwrap();
        let back: KycCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, back);
    }

    #[test]
    fn note_leaf_index_none_round_trip() {
        let note = Note {
            denomination: 500,
            salt: zero32(),
            receiver_pk: zero32(),
            leaf_index: None,
        };
        let json = serde_json::to_string(&note).unwrap();
        let back: Note = serde_json::from_str(&json).unwrap();
        assert_eq!(note, back);
    }
}
