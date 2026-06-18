use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::sha256::constraints::{Sha256Gadget, UnitVar};
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    select::CondSelectGadget,
    uint8::UInt8,
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// ZK circuit that proves a shielded withdrawal is valid.
///
/// Public inputs:
///   - `merkle_root`: current Merkle tree root (32 bytes)
///   - `nullifier`:   SHA-256(salt || receiver_pk) to prevent double-spend
///
/// Private witnesses:
///   - `denomination`:         transfer amount in stroops (> 0)
///   - `salt`:                 32-byte random blinding factor
///   - `receiver_pk`:          32-byte recipient shielded public key
///   - `merkle_path`:          20 sibling hashes
///   - `merkle_path_indices`:  path direction bits (false=left, true=right)
pub struct WithdrawalCircuit {
    pub merkle_root:         Option<[u8; 32]>,
    pub nullifier:           Option<[u8; 32]>,
    pub denomination:        Option<i64>,
    pub salt:                Option<[u8; 32]>,
    pub receiver_pk:         Option<[u8; 32]>,
    pub merkle_path:         Option<[[u8; 32]; 20]>,
    pub merkle_path_indices: Option<[bool; 20]>,
}

/// Invoke the SHA-256 constraint gadget over a byte slice.
fn sha256_gadget(
    input: &[UInt8<Fr>],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let params = UnitVar::default();
    let digest = <Sha256Gadget<Fr> as CRHSchemeGadget<_, Fr>>::evaluate(&params, input)?;
    Ok(digest.0.to_vec())
}

/// Allocate 32 bytes as witnesses.
fn alloc_32_witnesses(
    cs: ConstraintSystemRef<Fr>,
    val: Option<[u8; 32]>,
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut vars = Vec::with_capacity(32);
    for i in 0..32 {
        let byte = UInt8::new_witness(ark_relations::ns!(cs, "bytes32_w"), || {
            val.map(|b| b[i]).ok_or(SynthesisError::AssignmentMissing)
        })?;
        vars.push(byte);
    }
    Ok(vars)
}

impl ConstraintSynthesizer<Fr> for WithdrawalCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Allocate public inputs ──────────────────────────────────────────

        let mut merkle_root_vars: Vec<UInt8<Fr>> = Vec::with_capacity(32);
        for i in 0..32 {
            let byte = UInt8::new_input(ark_relations::ns!(cs, "merkle_root_byte"), || {
                self.merkle_root
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            merkle_root_vars.push(byte);
        }

        let mut nullifier_vars: Vec<UInt8<Fr>> = Vec::with_capacity(32);
        for i in 0..32 {
            let byte = UInt8::new_input(ark_relations::ns!(cs, "nullifier_byte"), || {
                self.nullifier
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            nullifier_vars.push(byte);
        }

        // ── Allocate private witnesses ──────────────────────────────────────

        let denom_val = self.denomination;
        let denom_bytes_val = denom_val.map(|d| d.to_be_bytes());

        let mut denom_byte_vars: Vec<UInt8<Fr>> = Vec::with_capacity(8);
        for i in 0..8 {
            let byte = UInt8::new_witness(ark_relations::ns!(cs, "denom_byte"), || {
                denom_bytes_val
                    .map(|b| b[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            denom_byte_vars.push(byte);
        }

        let salt_vars = alloc_32_witnesses(cs.clone(), self.salt)?;
        let pk_vars   = alloc_32_witnesses(cs.clone(), self.receiver_pk)?;

        // ── Constraint 1: commitment = SHA-256(denomination_be || salt || receiver_pk) ──

        let mut preimage_commit: Vec<UInt8<Fr>> = Vec::with_capacity(8 + 32 + 32);
        preimage_commit.extend_from_slice(&denom_byte_vars);
        preimage_commit.extend_from_slice(&salt_vars);
        preimage_commit.extend_from_slice(&pk_vars);

        let mut current: Vec<UInt8<Fr>> = sha256_gadget(&preimage_commit)?;

        // ── Constraint 2: Incremental Merkle path verification ─────────────
        //
        // For each of the 20 levels, conditionally swap left/right based on
        // the index bit, then hash the 64-byte concatenated pair.

        let merkle_path    = self.merkle_path;
        let merkle_indices = self.merkle_path_indices;

        for level in 0..20 {
            let index_bit = Boolean::new_witness(
                ark_relations::ns!(cs, "merkle_index_bit"),
                || {
                    merkle_indices
                        .map(|idx| idx[level])
                        .ok_or(SynthesisError::AssignmentMissing)
                },
            )?;

            let sibling_val = merkle_path.map(|p| p[level]);
            let mut sibling_vars: Vec<UInt8<Fr>> = Vec::with_capacity(32);
            for i in 0..32 {
                let byte = UInt8::new_witness(ark_relations::ns!(cs, "sibling_byte"), || {
                    sibling_val
                        .map(|s| s[i])
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;
                sibling_vars.push(byte);
            }

            // index_bit == false → left=current, right=sibling
            // index_bit == true  → left=sibling, right=current
            let mut left:  Vec<UInt8<Fr>> = Vec::with_capacity(32);
            let mut right: Vec<UInt8<Fr>> = Vec::with_capacity(32);
            for i in 0..32 {
                let l = UInt8::conditionally_select(&index_bit, &sibling_vars[i], &current[i])?;
                let r = UInt8::conditionally_select(&index_bit, &current[i], &sibling_vars[i])?;
                left.push(l);
                right.push(r);
            }

            let mut preimage_merkle: Vec<UInt8<Fr>> = Vec::with_capacity(64);
            preimage_merkle.extend_from_slice(&left);
            preimage_merkle.extend_from_slice(&right);

            current = sha256_gadget(&preimage_merkle)?;
        }

        // After 20 levels, current must equal merkle_root
        for (computed, expected) in current.iter().zip(merkle_root_vars.iter()) {
            computed.enforce_equal(expected)?;
        }

        // ── Constraint 3: nullifier = SHA-256(salt || receiver_pk) ─────────

        let mut preimage_null: Vec<UInt8<Fr>> = Vec::with_capacity(64);
        preimage_null.extend_from_slice(&salt_vars);
        preimage_null.extend_from_slice(&pk_vars);

        let nullifier_computed = sha256_gadget(&preimage_null)?;

        for (computed, expected) in nullifier_computed.iter().zip(nullifier_vars.iter()) {
            computed.enforce_equal(expected)?;
        }

        // ── Constraint 4: denomination > 0 ─────────────────────────────────

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
