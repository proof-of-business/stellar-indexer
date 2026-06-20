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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use sha2::{Digest, Sha256};

    // ── Merkle tree helpers ────────────────────────────────────────────────

    /// Compute `SHA-256(left || right)`.
    fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(left);
        h.update(right);
        h.finalize().into()
    }

    /// Pre-compute the 21 empty-subtree hashes (index 0 = leaf level).
    ///   empty[0] = SHA-256(b"zcash_merkle_leaf")
    ///   empty[i+1] = SHA-256(empty[i] || empty[i])
    fn empty_hashes() -> [[u8; 32]; 21] {
        let mut e = [[0u8; 32]; 21];
        e[0] = Sha256::digest(b"zcash_merkle_leaf").into();
        for i in 0..20 {
            let prev = e[i];
            e[i + 1] = sha256_pair(&prev, &prev);
        }
        e
    }

    /// Build a depth-20 Merkle path for a single commitment at leaf index 0.
    ///
    /// Returns `(root, siblings[20], indices[20])`.
    /// All indices are `false` (commitment is the left child at every level).
    fn build_merkle_path_for_leaf(
        commitment: [u8; 32],
    ) -> ([u8; 32], [[u8; 32]; 20], [bool; 20]) {
        let empty = empty_hashes();

        // At level 0 the sibling of our commitment is the empty leaf hash.
        let mut siblings = [[0u8; 32]; 20];
        let mut indices  = [false; 20];

        let mut current = commitment;
        for level in 0..20 {
            // Index bit = false  →  current is the left child
            siblings[level] = empty[level];
            indices[level]  = false;
            current = sha256_pair(&current, &empty[level]);
        }

        (current, siblings, indices)
    }

    // ── Shared test data ───────────────────────────────────────────────────

    const DENOMINATION: i64    = 1_000_000i64;
    const SALT:         [u8; 32] = [0x42u8; 32];
    const RECEIVER_PK:  [u8; 32] = [0x7fu8; 32];

    fn compute_commitment() -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DENOMINATION.to_be_bytes());
        h.update(SALT);
        h.update(RECEIVER_PK);
        h.finalize().into()
    }

    fn compute_nullifier() -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(SALT);
        h.update(RECEIVER_PK);
        h.finalize().into()
    }

    // ── Test 1: valid proof with correct 20-level Merkle path ─────────────
    #[test]
    fn test_valid_withdrawal_circuit() {
        let commitment = compute_commitment();
        let nullifier  = compute_nullifier();
        let (root, siblings, indices) = build_merkle_path_for_leaf(commitment);

        let circuit = WithdrawalCircuit {
            merkle_root:         Some(root),
            nullifier:           Some(nullifier),
            denomination:        Some(DENOMINATION),
            salt:                Some(SALT),
            receiver_pk:         Some(RECEIVER_PK),
            merkle_path:         Some(siblings),
            merkle_path_indices: Some(indices),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation must not error for valid witnesses");
        assert!(
            cs.is_satisfied().unwrap(),
            "valid withdrawal circuit should satisfy all constraints"
        );
    }

    // ── Test 2: flipping one sibling byte causes constraint failure ────────
    #[test]
    fn test_flipped_sibling_fails() {
        let commitment = compute_commitment();
        let nullifier  = compute_nullifier();
        let (root, mut siblings, indices) = build_merkle_path_for_leaf(commitment);

        // Corrupt one byte in the sibling at level 0
        siblings[0][0] ^= 0xff;

        let circuit = WithdrawalCircuit {
            merkle_root:         Some(root),
            nullifier:           Some(nullifier),
            denomination:        Some(DENOMINATION),
            salt:                Some(SALT),
            receiver_pk:         Some(RECEIVER_PK),
            merkle_path:         Some(siblings),
            merkle_path_indices: Some(indices),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation should not error (just produce unsatisfied system)");
        assert!(
            !cs.is_satisfied().unwrap(),
            "flipping a sibling byte should violate the Merkle-root constraint"
        );
    }

    // ── Test 3: flipping one path index causes constraint failure ──────────
    #[test]
    fn test_flipped_path_index_fails() {
        let commitment = compute_commitment();
        let nullifier  = compute_nullifier();
        let (root, siblings, mut indices) = build_merkle_path_for_leaf(commitment);

        // Flip the index bit at level 5
        indices[5] = !indices[5];

        let circuit = WithdrawalCircuit {
            merkle_root:         Some(root),
            nullifier:           Some(nullifier),
            denomination:        Some(DENOMINATION),
            salt:                Some(SALT),
            receiver_pk:         Some(RECEIVER_PK),
            merkle_path:         Some(siblings),
            merkle_path_indices: Some(indices),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation should not error (just produce unsatisfied system)");
        assert!(
            !cs.is_satisfied().unwrap(),
            "flipping a path-index bit should violate the Merkle-root constraint"
        );
    }

    // ── Test 4: incorrect nullifier (all-zeros) fails constraint 3 ────────
    #[test]
    fn test_wrong_nullifier_fails() {
        let commitment = compute_commitment();
        let (root, siblings, indices) = build_merkle_path_for_leaf(commitment);

        // Supply an all-zeros nullifier instead of SHA-256(salt || receiver_pk)
        let wrong_nullifier = [0u8; 32];

        let circuit = WithdrawalCircuit {
            merkle_root:         Some(root),
            nullifier:           Some(wrong_nullifier),
            denomination:        Some(DENOMINATION),
            salt:                Some(SALT),
            receiver_pk:         Some(RECEIVER_PK),
            merkle_path:         Some(siblings),
            merkle_path_indices: Some(indices),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint generation should not error (just produce unsatisfied system)");
        assert!(
            !cs.is_satisfied().unwrap(),
            "all-zeros nullifier should violate the nullifier equality constraint"
        );
    }
}
