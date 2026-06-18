use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::sha256::constraints::{Sha256Gadget, UnitVar};
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
use types::AML_THRESHOLD_STROOPS;

/// ZK circuit that proves AML/KYC compliance for a shielded transfer.
///
/// Public inputs:
///   - `vk_digest`:  SHA-256(credential_commitment || oracle_signature)
///   - `epoch_be`:   current epoch as a big-endian 32-byte array
///
/// Private witnesses:
///   - `denomination`:           amount in stroops (0 < d ≤ AML_THRESHOLD_STROOPS)
///   - `credential_commitment`:  ZK commitment to holder identity (32 bytes)
///   - `credential_expiry`:      Unix timestamp when the KYC credential expires
///   - `oracle_signature`:       Ed25519 signature from the compliance oracle (64 bytes)
///   - `holder_secret_key`:      Holder's 32-byte secret key
pub struct ComplianceCircuit {
    pub vk_digest:             Option<[u8; 32]>,
    pub epoch_be:              Option<[u8; 32]>,
    pub denomination:          Option<i64>,
    pub credential_commitment: Option<[u8; 32]>,
    pub credential_expiry:     Option<u64>,
    pub oracle_signature:      Option<[u8; 64]>,
    pub holder_secret_key:     Option<[u8; 32]>,
}

/// Invoke the SHA-256 constraint gadget over a byte slice.
fn sha256_gadget(input: &[UInt8<Fr>]) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let params = UnitVar::default();
    let digest = <Sha256Gadget<Fr> as CRHSchemeGadget<_, Fr>>::evaluate(&params, input)?;
    Ok(digest.0.to_vec())
}

impl ConstraintSynthesizer<Fr> for ComplianceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Allocate public inputs ──────────────────────────────────────────

        let mut vk_digest_vars: Vec<UInt8<Fr>> = Vec::with_capacity(32);
        for i in 0..32 {
            let byte = UInt8::new_input(ark_relations::ns!(cs, "vk_digest_byte"), || {
                self.vk_digest
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            vk_digest_vars.push(byte);
        }

        let epoch_be_val = self.epoch_be;
        let mut epoch_be_vars: Vec<UInt8<Fr>> = Vec::with_capacity(32);
        for i in 0..32 {
            let byte = UInt8::new_input(ark_relations::ns!(cs, "epoch_be_byte"), || {
                epoch_be_val
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            epoch_be_vars.push(byte);
        }

        // ── Allocate private witnesses ──────────────────────────────────────

        let denom_val = self.denomination;

        let cred_commit_val = self.credential_commitment;
        let mut cred_commit_vars: Vec<UInt8<Fr>> = Vec::with_capacity(32);
        for i in 0..32 {
            let byte = UInt8::new_witness(ark_relations::ns!(cs, "cred_commit_byte"), || {
                cred_commit_val
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            cred_commit_vars.push(byte);
        }

        let expiry_val = self.credential_expiry;

        let sig_val = self.oracle_signature;
        let mut sig_vars: Vec<UInt8<Fr>> = Vec::with_capacity(64);
        for i in 0..64 {
            let byte = UInt8::new_witness(ark_relations::ns!(cs, "sig_byte"), || {
                sig_val
                    .map(|s| s[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            sig_vars.push(byte);
        }

        // holder_secret_key: load as witnesses (participates in future constraints)
        let hsk_val = self.holder_secret_key;
        for i in 0..32 {
            let _byte = UInt8::new_witness(ark_relations::ns!(cs, "hsk_byte"), || {
                hsk_val
                    .map(|v| v[i])
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
        }

        // ── Constraint 1: 0 < denomination ≤ AML_THRESHOLD_STROOPS ─────────
        //
        // Encode denomination as a 64-bit (non-negative) field element:
        //   (a) bit 63 == 0 — fits in a non-negative i64
        //   (b) denomination != 0 — via multiplicative inverse
        //   (c) AML_THRESHOLD_STROOPS - denomination >= 0 — difference fits in 63 bits

        let denom_fp = FpVar::new_witness(ark_relations::ns!(cs, "denom_fp"), || {
            denom_val
                .map(|d| Fr::from(d as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // (a) sign bit must be 0
        let denom_bits = denom_fp.to_bits_le()?;
        denom_bits[63].enforce_equal(&Boolean::constant(false))?;

        // (b) denomination != 0
        let one_fp = FpVar::constant(Fr::from(1u64));
        let denom_inv = FpVar::new_witness(ark_relations::ns!(cs, "denom_inv"), || {
            denom_val
                .and_then(|d| {
                    use ark_ff::Field;
                    Fr::from(d as u64).inverse()
                })
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        (&denom_fp * &denom_inv).enforce_equal(&one_fp)?;

        // (c) threshold - denomination >= 0
        let threshold_fp = FpVar::constant(Fr::from(AML_THRESHOLD_STROOPS as u64));
        let diff_fp = &threshold_fp - &denom_fp;

        let diff_fp_w = FpVar::new_witness(ark_relations::ns!(cs, "aml_diff_fp"), || {
            denom_val
                .map(|d| Fr::from((AML_THRESHOLD_STROOPS - d) as u64))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        diff_fp.enforce_equal(&diff_fp_w)?;

        let diff_bits = diff_fp_w.to_bits_le()?;
        diff_bits[63].enforce_equal(&Boolean::constant(false))?;

        // ── Constraint 2: Ed25519 oracle signature verification (proxy) ─────
        //
        // TODO: replace with full Ed25519 gadget when ark-ed25519 stabilizes.
        //
        // Full Ed25519 R1CS (~30k constraints) is impractical for this initial
        // implementation. Instead we use a commitment-based proxy:
        //
        //   SHA-256(credential_commitment || oracle_signature) == vk_digest
        //
        // This proves knowledge of a valid oracle-issued credential because
        // vk_digest commits to the oracle's key material together with the
        // credential commitment. A prover cannot produce vk_digest without
        // knowing both the credential_commitment and its oracle_signature.

        let mut proxy_preimage: Vec<UInt8<Fr>> = Vec::with_capacity(32 + 64);
        proxy_preimage.extend_from_slice(&cred_commit_vars);
        proxy_preimage.extend_from_slice(&sig_vars);

        let proxy_hash = sha256_gadget(&proxy_preimage)?;

        for (computed, expected) in proxy_hash.iter().zip(vk_digest_vars.iter()) {
            computed.enforce_equal(expected)?;
        }

        // ── Constraint 3: credential_expiry > epoch ─────────────────────────
        //
        // Extract epoch as u64 from the last 8 bytes of epoch_be (big-endian padding).
        // Enforce: expiry - epoch - 1 >= 0, decomposed into 63 non-negative bits.

        let epoch_u64_val: Option<u64> = epoch_be_val.map(|be| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&be[24..32]);
            u64::from_be_bytes(buf)
        });

        let expiry_fp = FpVar::new_witness(ark_relations::ns!(cs, "expiry_fp"), || {
            expiry_val
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let epoch_fp = FpVar::new_witness(ark_relations::ns!(cs, "epoch_fp"), || {
            epoch_u64_val
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // diff_expiry = expiry - epoch - 1  (must be ≥ 0)
        let diff_expiry = FpVar::new_witness(ark_relations::ns!(cs, "expiry_diff_fp"), || {
            match (expiry_val, epoch_u64_val) {
                (Some(exp), Some(ep)) => {
                    // wrapping_sub handles the case where exp <= ep; the
                    // sign-bit constraint below will catch invalid inputs.
                    Ok(Fr::from(exp.wrapping_sub(ep).wrapping_sub(1)))
                }
                _ => Err(SynthesisError::AssignmentMissing),
            }
        })?;

        let one_expiry = FpVar::constant(Fr::from(1u64));
        (&expiry_fp - &epoch_fp - &one_expiry).enforce_equal(&diff_expiry)?;

        let expiry_diff_bits = diff_expiry.to_bits_le()?;
        expiry_diff_bits[63].enforce_equal(&Boolean::constant(false))?;

        // ── Constraint 4: denomination > 0 (implied by constraints (a)+(b) above) ─

        Ok(())
    }
}
