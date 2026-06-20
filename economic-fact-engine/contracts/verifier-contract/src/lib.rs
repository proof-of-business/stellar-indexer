#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, BytesN, Env, Vec,
};

/// Storage keys for the verifier contract.
/// `Admin` uses instance storage; VK keys use persistent storage.
#[contracttype]
#[derive(Clone)]
pub enum VerifierDataKey {
    /// Address of the 3-of-5 multisig admin (instance storage)
    Admin,
    /// Serialized Groth16 VerifyingKey for the Deposit circuit (circuit_id = 0)
    VkDeposit,
    /// Serialized Groth16 VerifyingKey for the Withdrawal circuit (circuit_id = 1)
    VkWithdrawal,
    /// Serialized Groth16 VerifyingKey for the Compliance circuit (circuit_id = 2)
    VkCompliance,
}

/// Errors returned by the verifier contract entry points.
/// `verify_proof` never returns an error — it returns `false` on any bad input.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VerifierError {
    /// Contract called before `initialize()`.
    NotInitialized = 1,
    /// `initialize()` was called more than once.
    AlreadyInitialized = 2,
    /// `circuit_id` is not 0, 1, or 2; only used internally — `verify_proof` returns `false`.
    UnknownCircuitId = 3,
    /// Caller of `rotate_vk` is not the stored admin.
    UnauthorizedRotation = 4,
    /// VK bytes cannot be deserialized into a valid VerifyingKey.
    InvalidVkBytes = 5,
}

#[contract]
pub struct VerifierContract;

#[contractimpl]
impl VerifierContract {
    /// Initialize the verifier with verification keys for all three circuits.
    ///
    /// Stores `admin` in instance storage and each VK in persistent storage.
    /// Emits `("init",) → (sha256(vk_deposit), sha256(vk_withdrawal), sha256(vk_compliance))`.
    /// Returns `AlreadyInitialized` if called a second time.
    pub fn initialize(
        env: Env,
        admin: Address,
        vk_deposit: Bytes,
        vk_withdrawal: Bytes,
        vk_compliance: Bytes,
    ) -> Result<(), VerifierError> {
        // Guard against double-initialization
        if env
            .storage()
            .instance()
            .has(&VerifierDataKey::Admin)
        {
            return Err(VerifierError::AlreadyInitialized);
        }

        // Store admin in instance storage
        env.storage()
            .instance()
            .set(&VerifierDataKey::Admin, &admin);

        // Store VKs in persistent storage
        env.storage()
            .persistent()
            .set(&VerifierDataKey::VkDeposit, &vk_deposit);
        env.storage()
            .persistent()
            .set(&VerifierDataKey::VkWithdrawal, &vk_withdrawal);
        env.storage()
            .persistent()
            .set(&VerifierDataKey::VkCompliance, &vk_compliance);

        // Emit initialization event with sha256 digests of each VK
        let digest_deposit: BytesN<32> = env.crypto().sha256(&vk_deposit);
        let digest_withdrawal: BytesN<32> = env.crypto().sha256(&vk_withdrawal);
        let digest_compliance: BytesN<32> = env.crypto().sha256(&vk_compliance);

        env.events().publish(
            ("init",),
            (digest_deposit, digest_withdrawal, digest_compliance),
        );

        Ok(())
    }

    /// Verify a Groth16 proof for the given circuit.
    ///
    /// Returns `false` (never panics) on any malformed, truncated, or arithmetically
    /// invalid input.  Unknown `circuit_id` values also return `false`.
    ///
    /// `circuit_id`: 0 = Deposit, 1 = Withdrawal, 2 = Compliance
    pub fn verify_proof(
        env: Env,
        circuit_id: u32,
        proof_bytes: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool {
        todo!()
    }

    /// Rotate a stored verification key (emergency use only).
    ///
    /// Requires authorization from the stored admin (3-of-5 multisig).
    /// Returns `UnauthorizedRotation` if the caller is not the admin.
    /// Returns `NotInitialized` if `initialize` has not been called.
    pub fn rotate_vk(
        env: Env,
        circuit_id: u32,
        new_vk: Bytes,
    ) -> Result<(), VerifierError> {
        todo!()
    }

    /// Return the SHA-256 digest of the stored VK for the given `circuit_id`.
    ///
    /// Useful for independent verification that the correct VK is deployed.
    /// Panics if `circuit_id` is unknown or the contract is not initialized.
    pub fn get_vk_digest(env: Env, circuit_id: u32) -> BytesN<32> {
        todo!()
    }
}
