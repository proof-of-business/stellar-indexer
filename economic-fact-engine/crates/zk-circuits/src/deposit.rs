use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    uint8::UInt8,
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

// UnitVar is the parameter type Sha256Gadget expects for its "Parameters"
use ark_crypto_primitives::crh::sha256::constraints::UnitVar;

/// ZK circuit that proves a shielded deposit is valid.
///
/// Public input:
///   - `commitment`: SHA-256 digest of `denomination_be || salt || receiver_pk`
///
/// Private witnesses:
///   - `denomination`: transfer amount in stroops (must be > 0)
///   - `salt`:         32-byte random blinding factor
///   - `receiver_pk`:  32-byte recipient shielded public key
pub struct DepositCircuit {
    pub commitment:   Option<Vec<u8>>,
    pub denomination: Option<i64>,
    pub salt:         Option<[u8; 32]>,
    pub receiver_pk:  Option<[u8; 32]>,
}

/// Allocate 8 big-endian bytes of a value as witnesses.
fn alloc_i64_be_witnesses(
    cs: ConstraintSystemRef<Fr>,
    val: Option<[u8; 8]>,
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut vars = Vec::with_capacity(8);
    for i in 0..8 {
        let byte = UInt8::new_witness(ark_relations::ns!(cs, "i64_be_byte"), || {
            val.map(|b| b[i]).ok_or(SynthesisError::AssignmentMissing)
        })?;
        vars.push(byte);
    }
    Ok(vars)
}

/// Allocate 32 bytes as witnesses.
fn alloc_32_witnesses(
    cs: ConstraintSystemRef<Fr>,
    val: Option<[u8; 32]>,
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut vars = Vec::with_capacity(32);
    for i in 0..32 {
        let byte = UInt8::new_witness(ark_relations::ns!(cs, "bytes32_witness"), || {
            val.map(|b| b[i]).ok_or(SynthesisError::AssignmentMissing)
        })?;
        vars.push(byte);
    }
    Ok(vars)
}

/// Invoke the SHA-256 constraint gadget over a byte slice.
fn sha256_gadget(input: &[UInt8<Fr>]) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    // Sha256Gadget expects a reference to UnitVar<Fr> for its (unused) parameters.
    let params = UnitVar::default();
    let digest = <Sha256Gadget<Fr> as CRHSchemeGadget<_, Fr>>::evaluate(&params, input)?;
    // DigestVar wraps [UInt8<Fr>; 32]; access via .0
    Ok(digest.0.to_vec())
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Allocate private witnesses ──────────────────────────────────────

        let denom_val = self.denomination;
        let denom_bytes_val = denom_val.map(|d| d.to_be_bytes());
        let denom_byte_vars = alloc_i64_be_witnesses(cs.clone(), denom_bytes_val)?;
        let salt_vars       = alloc_32_witnesses(cs.clone(), self.salt)?;
        let pk_vars         = alloc_32_witnesses(cs.clone(), self.receiver_pk)?;

        // ── Allocate public input: commitment (32 bytes) ────────────────────

        let commitment_val = self.commitment;
        let mut commitment_vars: Vec<UInt8<Fr>> = Vec::with_capacity(32);
        for i in 0..32 {
            let byte = UInt8::new_input(ark_relations::ns!(cs, "commitment_byte"), || {
                commitment_val
                    .as_ref()
                    .and_then(|v| v.get(i).copied())
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            commitment_vars.push(byte);
        }

        // ── Constraint 1: SHA-256(denomination_be || salt || receiver_pk) == commitment ──

        let mut preimage: Vec<UInt8<Fr>> = Vec::with_capacity(8 + 32 + 32);
        preimage.extend_from_slice(&denom_byte_vars);
        preimage.extend_from_slice(&salt_vars);
        preimage.extend_from_slice(&pk_vars);

        let computed_hash = sha256_gadget(&preimage)?;

        for (computed, expected) in computed_hash.iter().zip(commitment_vars.iter()) {
            computed.enforce_equal(expected)?;
        }

        // ── Constraint 2: denomination > 0 ─────────────────────────────────
        //
        // Allocate denomination as FpVar (treating the i64 bits as a u64).
        // (a) Decompose into 64 LE bits; bit 63 must be 0 (non-negative i64).
        // (b) Enforce non-zero via multiplicative inverse.

        let denom_fp = FpVar::new_witness(ark_relations::ns!(cs, "denom_fp"), || {
            denom_val
                .map(|d| Fr::from(d as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let bits = denom_fp.to_bits_le()?;
        bits[63].enforce_equal(&Boolean::constant(false))?;

        let one = FpVar::constant(Fr::from(1u64));
        let inv = FpVar::new_witness(ark_relations::ns!(cs, "denom_inv"), || {
            denom_val
                .and_then(|d| {
                    use ark_ff::Field;
                    Fr::from(d as u64).inverse()
                })
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        (&denom_fp * &inv).enforce_equal(&one)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use sha2::{Digest, Sha256};

    /// Build a correct SHA-256 commitment for the given preimage.
    fn compute_commitment(denomination: i64, salt: [u8; 32], receiver_pk: [u8; 32]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(denomination.to_be_bytes());
        hasher.update(salt);
        hasher.update(receiver_pk);
        hasher.finalize().to_vec()
    }

    /// Test 1: a valid (denomination, salt, receiver_pk) triple satisfies all constraints.
    #[test]
    fn test_valid_deposit_circuit() {
        let denomination: i64 = 1_000_000; // 1 XLM in stroops, positive
        let salt = [0x42u8; 32];
        let receiver_pk = [0x7fu8; 32];
        let commitment = compute_commitment(denomination, salt, receiver_pk);

        let circuit = DepositCircuit {
            commitment:   Some(commitment),
            denomination: Some(denomination),
            salt:         Some(salt),
            receiver_pk:  Some(receiver_pk),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("constraint generation should not error");
        assert!(
            cs.is_satisfied().unwrap(),
            "valid deposit circuit should satisfy all constraints"
        );
    }

    /// Test 2: a commitment that does NOT match the preimage fails constraint 1.
    #[test]
    fn test_mismatched_commitment_fails() {
        let denomination: i64 = 5_000_000;
        let salt = [0x11u8; 32];
        let receiver_pk = [0x22u8; 32];
        // Deliberately wrong commitment: all zeros
        let wrong_commitment = vec![0u8; 32];

        let circuit = DepositCircuit {
            commitment:   Some(wrong_commitment),
            denomination: Some(denomination),
            salt:         Some(salt),
            receiver_pk:  Some(receiver_pk),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("constraint generation should not error");
        assert!(
            !cs.is_satisfied().unwrap(),
            "mismatched commitment should fail the hash equality constraint"
        );
    }

    /// Test 3: denomination = 0 with a correctly computed commitment fails the range check constraint.
    #[test]
    fn test_zero_denomination_fails() {
        let denomination: i64 = 0;
        let salt = [0xabu8; 32];
        let receiver_pk = [0xcdu8; 32];
        // Commitment is correct for denomination=0, so constraint 1 passes;
        // constraint 2 (denomination > 0) must catch it.
        let commitment = compute_commitment(denomination, salt, receiver_pk);

        let circuit = DepositCircuit {
            commitment:   Some(commitment),
            denomination: Some(denomination),
            salt:         Some(salt),
            receiver_pk:  Some(receiver_pk),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        // generate_constraints may itself return an error (e.g., inverse of 0 is undefined),
        // or it may succeed but leave the system unsatisfied.  Either outcome confirms the
        // zero-denomination is rejected.
        let result = circuit.generate_constraints(cs.clone());
        let rejected = result.is_err() || !cs.is_satisfied().unwrap_or(false);
        assert!(
            rejected,
            "denomination = 0 should be rejected by the range-check constraint"
        );
    }
}
