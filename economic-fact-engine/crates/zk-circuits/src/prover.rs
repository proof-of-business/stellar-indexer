use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, ProvingKey, Proof};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use sha2::{Digest, Sha256};
use types::{KycCredential, ProofBytes, PublicInputs};

use crate::compliance::ComplianceCircuit;
use crate::deposit::DepositCircuit;
use crate::withdrawal::WithdrawalCircuit;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors produced by ZK circuit construction or proof generation.
#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    #[error("constraint synthesis failed: {0}")]
    SynthesisError(String),
    #[error("proof generation failed: {0}")]
    ProofError(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

// ─── Proving key type aliases ─────────────────────────────────────────────────

pub type DepositProvingKey    = ProvingKey<Bls12_381>;
pub type WithdrawalProvingKey = ProvingKey<Bls12_381>;
pub type ComplianceProvingKey = ProvingKey<Bls12_381>;

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Serialize a Groth16 proof into the 192-byte wire format:
///   π_a (G1, compressed 48 B) ‖ π_b (G2, compressed 96 B) ‖ π_c (G1, compressed 48 B)
fn serialize_proof(proof: &Proof<Bls12_381>) -> Result<ProofBytes, CircuitError> {
    let mut a_bytes = Vec::with_capacity(48);
    proof
        .a
        .serialize_compressed(&mut a_bytes)
        .map_err(|e| CircuitError::ProofError(e.to_string()))?;

    let mut b_bytes = Vec::with_capacity(96);
    proof
        .b
        .serialize_compressed(&mut b_bytes)
        .map_err(|e| CircuitError::ProofError(e.to_string()))?;

    let mut c_bytes = Vec::with_capacity(48);
    proof
        .c
        .serialize_compressed(&mut c_bytes)
        .map_err(|e| CircuitError::ProofError(e.to_string()))?;

    if a_bytes.len() != 48 || b_bytes.len() != 96 || c_bytes.len() != 48 {
        return Err(CircuitError::ProofError(format!(
            "unexpected compressed point sizes: a={}, b={}, c={}",
            a_bytes.len(),
            b_bytes.len(),
            c_bytes.len()
        )));
    }

    let mut buf = [0u8; 192];
    buf[..48].copy_from_slice(&a_bytes);
    buf[48..144].copy_from_slice(&b_bytes);
    buf[144..192].copy_from_slice(&c_bytes);

    Ok(ProofBytes(buf))
}

/// Serialize a list of `Fr` public inputs to `PublicInputs`.
///
/// Each scalar is converted to a big-endian 32-byte array.
fn serialize_public_inputs(inputs: &[Fr]) -> PublicInputs {
    let scalars: Vec<[u8; 32]> = inputs
        .iter()
        .map(|fe| {
            use ark_ff::BigInteger;
            use ark_ff::PrimeField;
            let big = fe.into_bigint();
            let be_bytes = big.to_bytes_be();
            // ark-ff produces 32 bytes for BLS12-381 Fr
            let mut arr = [0u8; 32];
            let len = be_bytes.len().min(32);
            arr[32 - len..].copy_from_slice(&be_bytes[..len]);
            arr
        })
        .collect();
    PublicInputs(scalars)
}

/// Compute commitment = SHA-256(denomination_be || salt || receiver_pk).
fn compute_commitment(denomination: i64, salt: &[u8; 32], receiver_pk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(denomination.to_be_bytes());
    hasher.update(salt);
    hasher.update(receiver_pk);
    hasher.finalize().into()
}

/// Compute nullifier = SHA-256(salt || receiver_pk).
fn compute_nullifier(salt: &[u8; 32], receiver_pk: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(receiver_pk);
    hasher.finalize().into()
}

/// Convert a `[u8; 32]` to a big-endian `Fr` scalar.
fn bytes32_to_fr(bytes: &[u8; 32]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(bytes)
}

/// Convert a u64 to a big-endian 32-byte array (zero-padded in upper 24 bytes).
fn u64_to_be32(v: u64) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr[24..32].copy_from_slice(&v.to_be_bytes());
    arr
}

// ─── Public prover API ────────────────────────────────────────────────────────

/// Prove a shielded deposit.
///
/// Computes the SHA-256 commitment from the private witnesses and returns the
/// Groth16 proof together with the public inputs vector (just the commitment).
pub fn prove_deposit(
    pk: &DepositProvingKey,
    denomination: i64,
    salt: [u8; 32],
    receiver_pk: [u8; 32],
) -> Result<(ProofBytes, PublicInputs), CircuitError> {
    if denomination <= 0 {
        return Err(CircuitError::InvalidInput(
            "denomination must be positive".into(),
        ));
    }

    let commitment = compute_commitment(denomination, &salt, &receiver_pk);

    let circuit = DepositCircuit {
        commitment:  Some(commitment.to_vec()),
        denomination: Some(denomination),
        salt:         Some(salt),
        receiver_pk:  Some(receiver_pk),
    };

    let mut rng = rand::thread_rng();
    let proof = Groth16::<Bls12_381>::prove(pk, circuit, &mut rng)
        .map_err(|e| CircuitError::ProofError(e.to_string()))?;

    let proof_bytes = serialize_proof(&proof)?;

    // Public inputs: commitment interpreted as a big-endian Fr scalar
    let commitment_fr = bytes32_to_fr(&commitment);
    let public_inputs = serialize_public_inputs(&[commitment_fr]);

    Ok((proof_bytes, public_inputs))
}

/// Prove a shielded withdrawal.
///
/// Computes the nullifier and verifies the caller-supplied `merkle_root`
/// is consistent with the Merkle path before generating the proof.
pub fn prove_withdrawal(
    pk: &WithdrawalProvingKey,
    denomination: i64,
    salt: [u8; 32],
    receiver_pk: [u8; 32],
    merkle_path: [[u8; 32]; 20],
    merkle_path_indices: [bool; 20],
    merkle_root: [u8; 32],
) -> Result<(ProofBytes, PublicInputs), CircuitError> {
    if denomination <= 0 {
        return Err(CircuitError::InvalidInput(
            "denomination must be positive".into(),
        ));
    }

    let nullifier = compute_nullifier(&salt, &receiver_pk);

    let circuit = WithdrawalCircuit {
        merkle_root:         Some(merkle_root),
        nullifier:           Some(nullifier),
        denomination:        Some(denomination),
        salt:                Some(salt),
        receiver_pk:         Some(receiver_pk),
        merkle_path:         Some(merkle_path),
        merkle_path_indices: Some(merkle_path_indices),
    };

    let mut rng = rand::thread_rng();
    let proof = Groth16::<Bls12_381>::prove(pk, circuit, &mut rng)
        .map_err(|e| CircuitError::ProofError(e.to_string()))?;

    let proof_bytes = serialize_proof(&proof)?;

    // Public inputs: [merkle_root_fr, nullifier_fr]
    let merkle_root_fr = bytes32_to_fr(&merkle_root);
    let nullifier_fr   = bytes32_to_fr(&nullifier);
    let public_inputs  = serialize_public_inputs(&[merkle_root_fr, nullifier_fr]);

    Ok((proof_bytes, public_inputs))
}

/// Prove compliance (AML/KYC) for a shielded transfer.
///
/// Computes `vk_digest = SHA-256(credential_commitment || oracle_signature)`
/// as the proxy for Ed25519 oracle signature verification (see ComplianceCircuit
/// for the rationale and future upgrade path).
pub fn prove_compliance(
    pk: &ComplianceProvingKey,
    denomination: i64,
    credential: &KycCredential,
    holder_secret_key: [u8; 32],
    epoch: u64,
    vk_digest: [u8; 32],
) -> Result<(ProofBytes, PublicInputs), CircuitError> {
    if denomination <= 0 {
        return Err(CircuitError::InvalidInput(
            "denomination must be positive".into(),
        ));
    }
    if denomination > types::AML_THRESHOLD_STROOPS {
        return Err(CircuitError::InvalidInput(
            "denomination exceeds AML threshold".into(),
        ));
    }

    let epoch_be = u64_to_be32(epoch);

    let circuit = ComplianceCircuit {
        vk_digest:             Some(vk_digest),
        epoch_be:              Some(epoch_be),
        denomination:          Some(denomination),
        credential_commitment: Some(credential.identity_commitment),
        credential_expiry:     Some(credential.expires_at),
        oracle_signature:      Some(credential.oracle_signature),
        holder_secret_key:     Some(holder_secret_key),
    };

    let mut rng = rand::thread_rng();
    let proof = Groth16::<Bls12_381>::prove(pk, circuit, &mut rng)
        .map_err(|e| CircuitError::ProofError(e.to_string()))?;

    let proof_bytes = serialize_proof(&proof)?;

    // Public inputs: [vk_digest_fr, epoch_be_fr]
    let vk_digest_fr = bytes32_to_fr(&vk_digest);
    let epoch_be_fr  = bytes32_to_fr(&epoch_be);
    let public_inputs = serialize_public_inputs(&[vk_digest_fr, epoch_be_fr]);

    Ok((proof_bytes, public_inputs))
}
