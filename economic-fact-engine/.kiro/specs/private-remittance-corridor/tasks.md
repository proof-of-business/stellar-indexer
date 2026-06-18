# Implementation Plan: Private Cross-Border Remittance Corridor

## Overview

This plan builds the full USD→MXN private remittance corridor in dependency order across a Rust workspace:
shared types and errors first, then ZK circuits, on-chain contracts (verifier then pool), off-chain services
(compliance oracle, corridor SDK, on-ramp, off-ramp), and finally end-to-end integration tests and trusted-setup
tooling. Each wave is independent within itself; later waves build on the artifacts from earlier ones.

All code uses Rust. Soroban contracts use `soroban-sdk`. Off-chain services use `tokio` + `reqwest`.
ZK circuits use `ark-groth16` + `ark-bls12-381` + `ark-crypto-primitives`. Property tests use `proptest`.
Integration tests use `soroban-sdk::testutils` + `wiremock`.

---

## Tasks

- [-] 1. Workspace scaffold — Cargo workspace, shared types, and shared errors

  - [x] 1.1 Create Cargo workspace with all crate members
    - Create root `Cargo.toml` declaring workspace members:
      `contracts/shielded-pool`, `contracts/verifier-contract`,
      `crates/types`, `crates/errors`, `crates/zk-circuits`, `crates/corridor-sdk`,
      `services/on-ramp-service`, `services/off-ramp-service`, `services/compliance-oracle`
    - Add workspace-level `[patch.crates-io]` stubs for `soroban-sdk` pinned version
    - Create skeleton `Cargo.toml` and `src/lib.rs` (or `src/main.rs`) for each member
    - _Requirements: 10.1 (single corridor scope)_

  - [x] 1.2 Implement `crates/types` — shared domain types
    - Define `Note { denomination: i64, salt: [u8;32], receiver_pk: [u8;32], leaf_index: Option<u32> }`
    - Define `Commitment([u8;32])`, `Nullifier([u8;32])`, `ProofBytes([u8;192])`,
      `PublicInputs(Vec<[u8;32]>)`, `MerklePath { siblings: [[u8;32];20], indices: [bool;20], leaf_index: u32 }`
    - Define `KycCredential { credential_id: String, issued_at: u64, expires_at: u64, identity_commitment: [u8;32], oracle_signature: [u8;64] }`
    - Add constants: `AML_THRESHOLD_STROOPS: i64 = 99_999_999_999`, `USDC_ISSUER`, `USDC_CODE`, `TREE_DEPTH: usize = 20`
    - Derive `serde::Serialize/Deserialize`, `Clone`, `Debug` on all types
    - _Requirements: 1.2, 2.1, 3.1, 3.3, 9.5_

  - [ ] 1.3 Implement `crates/errors` — shared `CorridorError` enum
    - Define `CorridorError` using `thiserror::Error` with all 11 variants:
      `ProofVerificationFailed`, `NullifierAlreadySpent`, `NoteAlreadyRedeemed`,
      `DepositAtomicityFailure`, `UnshieldedDepositRejected`, `PoolCapacityExceeded`,
      `InvalidAmount`, `InvalidCredential`, `CredentialExpired`,
      `OfframpSettlementTimeout`, `AnchorIntegrationFailure`
    - Add `#[serde(tag = "code", content = "detail")]` for structured JSON serialization
    - Ensure no variant's `Display` output includes denomination, identity, Note preimage, or credential fields
    - _Requirements: 8.1, 8.3, 8.4_

  - [ ]* 1.4 Write property test for `CorridorError` structured completeness
    - **Property 18: Structured error completeness**
    - For each CorridorError variant, assert serialization round-trips and contains none of:
      amount literals, identity strings, or Note preimage data
    - **Validates: Requirements 8.1, 8.3, 8.4**


- [ ] 2. ZK circuits — Groth16/BLS12-381 R1CS constraints and prover API

  - [ ] 2.1 Implement `Deposit_Circuit` R1CS constraints
    - In `crates/zk-circuits/src/deposit.rs`, define `DepositCircuit` implementing `ark_relations::r1cs::ConstraintSynthesizer<Fr>`
    - Wire `ark-crypto-primitives` SHA-256 gadget: `sha256_gadget(denomination_be || salt_be || receiver_pk_be) == commitment`
    - Add range check constraint: `denomination > 0`
    - Public input: `commitment` (32-byte Fr element)
    - Private witnesses: `denomination: i64`, `salt: [u8;32]`, `receiver_pk: [u8;32]`
    - _Requirements: 3.1, 3.2_

  - [ ]* 2.2 Write unit tests for `Deposit_Circuit` with known-good inputs
    - Test that a valid `(denomination, salt, receiver_pk)` triple satisfies all constraints
    - Test that a mismatched commitment fails constraint synthesis
    - Test that `denomination = 0` fails the range check constraint
    - _Requirements: 3.1, 3.2_

  - [ ] 2.3 Implement `Withdrawal_Circuit` R1CS constraints
    - In `crates/zk-circuits/src/withdrawal.rs`, define `WithdrawalCircuit`
    - Constraint 1: `commitment = sha256_gadget(denomination_be || salt_be || receiver_pk_be)`
    - Constraint 2: `merkle_root == incremental_merkle_verify(commitment, path, indices)` using SHA-256 at each node
    - Constraint 3: `nullifier == sha256_gadget(salt || receiver_pk)`
    - Constraint 4: `denomination > 0`
    - Public inputs: `merkle_root`, `nullifier`; private: `denomination`, `salt`, `receiver_pk`, `merkle_path`, `merkle_path_indices`
    - _Requirements: 3.3, 3.4_

  - [ ]* 2.4 Write unit tests for `Withdrawal_Circuit` with known-good inputs
    - Test valid proof with correct Merkle path at depth 20
    - Test that flipping one sibling hash causes constraint failure
    - Test that flipping one path index causes constraint failure
    - Test that incorrect nullifier fails constraint 3
    - _Requirements: 3.4_

  - [ ] 2.5 Implement `Compliance_Circuit` R1CS constraints
    - In `crates/zk-circuits/src/compliance.rs`, define `ComplianceCircuit`
    - Constraint 1: `denomination < AML_THRESHOLD_STROOPS + 1` (range check)
    - Constraint 2: Ed25519 signature gadget — `oracle_sig_verify(identity_commitment, oracle_signature, oracle_vk) == true`
    - Constraint 3: `credential_expiry > epoch_be` (not expired)
    - Constraint 4: `denomination > 0`
    - Public inputs: `vk_digest`, `epoch_be`; private: `denomination`, `credential_commitment`, `credential_expiry`, `oracle_signature`, `holder_secret_key`
    - _Requirements: 3.5, 3.6_

  - [ ]* 2.6 Write unit tests for `Compliance_Circuit` with known-good inputs
    - Test valid proof with `denomination = AML_THRESHOLD_STROOPS - 1` (boundary: just under)
    - Test that `denomination = AML_THRESHOLD_STROOPS` (100_000_000_000) fails constraint 1
    - Test that expired credential (`expiry < epoch`) fails constraint 3
    - Test that invalid oracle signature fails constraint 2
    - _Requirements: 3.6, 5.7_

  - [ ] 2.7 Implement prover API in `crates/zk-circuits/src/prover.rs`
    - Implement `prove_deposit(pk, denomination, salt, receiver_pk) -> Result<(ProofBytes, PublicInputs), CircuitError>`
    - Implement `prove_withdrawal(pk, denomination, salt, receiver_pk, merkle_path, indices, merkle_root) -> Result<(ProofBytes, PublicInputs), CircuitError>`
    - Implement `prove_compliance(pk, denomination, credential, holder_secret_key, epoch, vk_digest) -> Result<(ProofBytes, PublicInputs), CircuitError>`
    - Serialize proof as `π_a(48B) || π_b(96B) || π_c(48B)` = 192 bytes total
    - Serialize public inputs as big-endian 32-byte BLS12-381 Fr scalars with 4-byte big-endian length prefix
    - _Requirements: 3.10, 9.1, 9.3_

  - [ ]* 2.8 Write property test for proof serialization round-trip
    - **Property 14: Proof serialization round-trip**
    - Use `proptest` to generate arbitrary valid `(denomination, salt, receiver_pk)` triples
    - For each: prove_deposit → serialize ProofBytes → deserialize → re-verify with test VK → must accept
    - Repeat same pattern for `prove_withdrawal` and `prove_compliance`
    - **Validates: Requirements 9.2**

  - [ ]* 2.9 Write property test for Note field serialization round-trip
    - **Property 15: Note field serialization round-trip**
    - Use `proptest` with `denomination in (1..AML_THRESHOLD_STROOPS)`, arbitrary `salt: [u8;32]`, `receiver_pk: [u8;32]`
    - Assert `Note::from_bytes(note.to_bytes()) == note` exactly for all fields
    - **Validates: Requirements 9.5**


- [ ] 3. Checkpoint — ZK circuit layer
  - Ensure all circuit unit tests and property tests pass: `cargo test -p zk-circuits`
  - Ask the user if circuit constraints or the prover API need adjustment before proceeding.

- [ ] 4. `verifier-contract` — on-chain Groth16 verifier

  - [ ] 4.1 Implement `VerifierDataKey` storage enum and contract skeleton
    - In `contracts/verifier-contract/src/lib.rs`, define `VerifierDataKey { Admin, VkDeposit, VkWithdrawal, VkCompliance }` 
    - Define `VerifierError` as `#[contracterror]` enum with 5 variants (NotInitialized, AlreadyInitialized, UnknownCircuitId, UnauthorizedRotation, InvalidVkBytes)
    - Stub out all entry-point function signatures
    - _Requirements: 3.7, 8.2_

  - [ ] 4.2 Implement `initialize` entry point
    - Store `admin: Address` in instance storage
    - Deserialize and store `vk_deposit`, `vk_withdrawal`, `vk_compliance` as persistent `Bytes`
    - Return `AlreadyInitialized` if called twice
    - Emit initialization event: `("init",) → (sha256(vk_deposit), sha256(vk_withdrawal), sha256(vk_compliance))`
    - _Requirements: 3.9, 7.4_

  - [ ] 4.3 Implement `verify_proof` entry point with circuit_id routing
    - Route `circuit_id` 0/1/2 to the corresponding stored VK bytes; return `false` (not an error) for unknown ids
    - Deserialize `proof_bytes` (192 bytes) into `(π_a, π_b, π_c)` BLS12-381 points
    - Deserialize `public_inputs` (length-prefixed big-endian scalars)
    - Call CAP-0059 `env.bls12_381_g1_add` / pairing host functions to execute Groth16 verification
    - Return `false` (never panic) on any malformed or arithmetically invalid input
    - _Requirements: 3.7, 3.8, 9.4_

  - [ ] 4.4 Implement `rotate_vk` and `get_vk_digest` entry points
    - `rotate_vk`: require `admin` authorization (3-of-5 multisig); replace stored VK bytes; return `UnauthorizedRotation` if not admin
    - `get_vk_digest`: compute and return `SHA-256(stored_vk_bytes)` for the requested `circuit_id`
    - _Requirements: 7.2, 7.5_

  - [ ]* 4.5 Write Soroban testutils unit tests for `verifier-contract`
    - Test `initialize` stores VKs and emits correct digest event (Property 17)
    - Test `verify_proof` returns `true` for a real Groth16 proof generated by the circuit tests
    - Test `verify_proof` returns `false` for empty bytes, random 192 bytes, and truncated proofs
    - Test `rotate_vk` succeeds with admin key and fails with non-admin
    - _Requirements: 3.7, 3.8, 7.4, 7.5_

  - [ ]* 4.6 Write property test for `verify_proof` false-return on corrupted bytes
    - **Property 13: Verifier graceful false on malformed input**
    - Use `proptest` to generate arbitrary `Vec<u8>` of lengths 0, 1, 191, 192, 193, and 1024
    - For each: call `verify_proof(circuit_id, bytes, valid_inputs)` — assert returns `false`, no panic
    - Also flip individual bytes in a valid 192-byte proof and assert `false`
    - **Validates: Requirements 3.8, 9.4**

  - [ ]* 4.7 Write property test for verifier initialization event integrity
    - **Property 17: Verifier initialization event integrity**
    - Deploy verifier-contract with arbitrary valid VK bytes
    - Capture emitted `("init",)` event; assert each digest == `SHA-256(vk_bytes)` passed in
    - **Validates: Requirements 7.4**


- [ ] 5. `shielded-pool` — on-chain Merkle commitment pool

  - [ ] 5.1 Implement `PoolDataKey` storage enum, `PoolError`, and contract skeleton
    - Define `PoolDataKey { Admin, VerifierContract, UsdcAsset, NextIndex, MerkleRoot, FilledSubtree(u32), Nullifier(BytesN<32>) }`
    - Define `PoolError` as `#[contracterror]` enum with 8 variants
    - Stub all entry-point signatures
    - _Requirements: 2.1, 8.2_

  - [ ] 5.2 Implement `initialize` entry point and empty-tree setup
    - Store `admin`, `verifier_contract`, `usdc_asset` in instance storage
    - Pre-compute and store `FilledSubtree(i)` for all levels 0..19 using empty leaf hash `SHA-256(b"zcash_merkle_leaf")`
    - Initialize `NextIndex = 0`, `MerkleRoot` = root of empty depth-20 tree
    - Return `AlreadyInitialized` if called twice
    - _Requirements: 2.1_

  - [ ] 5.3 Implement incremental Merkle tree insert logic
    - In `contracts/shielded-pool/src/merkle.rs`, write `insert_leaf(env, commitment) -> (new_root, leaf_index)`
    - Use FilledSubtree pattern: for each level, if `leaf_index` bit is 0 store sibling; if 1 hash with stored sibling
    - Each insert reads/writes at most 20 `FilledSubtree` entries (O(depth))
    - Update `MerkleRoot` and increment `NextIndex`
    - Return `PoolCapacityExceeded` when `NextIndex == 2^20`
    - _Requirements: 2.1, 2.2, 2.9_

  - [ ] 5.4 Implement `deposit` entry point
    - Validate `amount > 0` → else `InvalidAmount`
    - Call `verifier_contract.verify_proof(0, deposit_proof, [commitment])` → false: `ProofVerificationFailed`
    - Call `verifier_contract.verify_proof(2, compliance_proof, compliance_public_inputs)` → false: `ProofVerificationFailed`
    - Pull USDC from caller into pool account atomically
    - Call `insert_leaf(commitment)` → get `leaf_index`
    - Emit event: `("deposit",) → (commitment, leaf_index)` — no amount, no identity
    - Return `leaf_index`
    - _Requirements: 1.3, 1.4, 1.8, 2.2, 2.4, 6.3_

  - [ ] 5.5 Implement nullifier spent-set logic and `withdraw` entry point
    - Check `Nullifier(nullifier)` not in storage → else `NullifierAlreadySpent`
    - Validate `merkle_root` matches stored `MerkleRoot` → else `RootMismatch`
    - Call `verifier_contract.verify_proof(1, withdrawal_proof, [merkle_root, nullifier])` → false: `ProofVerificationFailed`
    - Call `verifier_contract.verify_proof(2, compliance_proof, compliance_public_inputs)` → false: `ProofVerificationFailed`
    - Record `Nullifier(nullifier) = true` in persistent storage
    - Transfer USDC from pool to `recipient`
    - Emit event: `("withdrawal",) → (nullifier, leaf_index)` — no amount, no identity
    - _Requirements: 2.5, 2.6, 2.7, 6.4_

  - [ ] 5.6 Implement `get_root` and `get_leaf_count` read entry points
    - `get_root`: return `MerkleRoot` from storage
    - `get_leaf_count`: return `NextIndex` from storage
    - _Requirements: 2.8_

  - [ ]* 5.7 Write Soroban testutils unit tests for `shielded-pool`
    - Test `deposit` with valid proofs: assert leaf_index increments, root changes, event fields correct
    - Test `deposit` with zero/negative amount: assert `InvalidAmount`
    - Test `deposit` with invalid proof: assert `ProofVerificationFailed`
    - Test `withdraw` happy path: nullifier recorded, USDC transferred, event emitted
    - Test second `withdraw` with same nullifier: assert `NullifierAlreadySpent`
    - Test deposit when tree full (mock `NextIndex = 2^20`): assert `PoolCapacityExceeded`
    - _Requirements: 2.2, 2.6, 2.9, 2.10_

  - [ ]* 5.8 Write property test for Merkle insert consistency
    - **Property 4: Merkle tree insert consistency**
    - Use `proptest` to generate sequences of 1..50 distinct 32-byte commitments
    - After each insert, assert `leaf_count == n` and stored root equals SHA-256 incremental root computed off-chain
    - **Validates: Requirements 2.2**

  - [ ]* 5.9 Write property test for double-spend prevention
    - **Property 5: Double-spend prevention**
    - For any nullifier that completes a successful withdrawal, assert all subsequent withdrawals with the same nullifier return `NullifierAlreadySpent` regardless of proof bytes or Merkle root
    - Use `proptest` to vary proof bytes and roots
    - **Validates: Requirements 2.6**

  - [ ]* 5.10 Write property tests for deposit/withdrawal event privacy
    - **Property 6: Deposit event privacy**
    - Assert every deposit event payload contains exactly `(commitment, leaf_index)` and no denomination, sender, or receiver_pk
    - **Property 7: Withdrawal event privacy**
    - Assert every withdrawal event payload contains exactly `(nullifier, leaf_index)` and no amount or account identifier
    - **Property 8: Unshielded deposit rejection**
    - Assert any USDC transfer without proof returns `UnshieldedDepositRejected`
    - **Validates: Requirements 2.4, 2.10, 6.3, 6.4**

  - [ ]* 5.11 Write integration test for full deposit + withdrawal cycle
    - Deploy verifier-contract and shielded-pool in testutils environment with real ZK proofs (from `zk-circuits`)
    - Execute: deposit(commitment, proofs) → get leaf_index → build Merkle path → prove withdrawal → withdraw
    - Assert USDC balances, nullifier recorded, both events have correct payloads
    - _Requirements: 1.8, 2.2, 2.7_


- [ ] 6. Checkpoint — on-chain contracts
  - Ensure all contract unit and property tests pass: `cargo test -p verifier-contract -p shielded-pool`
  - Ask the user if storage layout or event schemas need adjustment before proceeding.

- [ ] 7. `compliance-oracle` — KYC credential issuance service

  - [ ] 7.1 Implement `KycCredential` issuance and Ed25519 signing
    - In `services/compliance-oracle/src/issuance.rs`, implement `issue_credential(identity_commitment: [u8;32], expires_at: u64) -> KycCredential`
    - Generate UUID v4 `credential_id`; set `issued_at = now()`
    - Sign `credential_id_bytes || issued_at_be || expires_at_be || identity_commitment` with oracle Ed25519 private key
    - Store `AuditLogEntry { credential_id, issued_at, expires_at }` in append-only log (no identity fields)
    - _Requirements: 5.1, 5.2, 5.8_

  - [ ] 7.2 Implement credential expiry and revocation
    - `revoke_credential(credential_id)`: re-issue with `expires_at = issued_at - 1` (past expiry)
    - Implement `is_expired(credential: &KycCredential, epoch: u64) -> bool` checking `expires_at < epoch`
    - _Requirements: 5.3, 5.7_

  - [ ] 7.3 Implement `GET /oracle/info` and `POST /oracle/credential` HTTP endpoints
    - `GET /oracle/info` → `OraclePublicInfo { vk_digest, current_epoch, transition_vk_digest: Option }`
    - `POST /oracle/credential` (authenticated) → `KycCredential`; gated by pre-shared API key
    - Use `axum` or `actix-web`; return structured JSON; no identity attributes in response bodies
    - _Requirements: 5.4, 5.5_

  - [ ] 7.4 Implement key rotation with 90-day transition window
    - On rotation: update active signing key; store previous key with `transition_expires_at = now + 90_days`
    - `GET /oracle/info` includes `transition_vk_digest` while transition window is active
    - Proofs referencing old VK digest remain valid until `transition_expires_at`
    - _Requirements: 5.6_

  - [ ]* 7.5 Write unit tests for credential issuance, expiry, and revocation
    - Test `issue_credential` produces valid Ed25519 signature verifiable with oracle public key
    - Test `is_expired` returns `true` when `expires_at < epoch` and `false` when `expires_at >= epoch`
    - Test `revoke_credential` produces credential with `expires_at < issued_at`
    - Test audit log entry contains only `(credential_id, issued_at, expires_at)` — no identity fields
    - _Requirements: 5.1, 5.3, 5.7, 5.8_

  - [ ]* 7.6 Write property test for audit log completeness and privacy
    - **Property 16: Audit log completeness and privacy**
    - Use `proptest` to issue N arbitrary credentials; assert every credential has a matching audit log entry
    - Assert no audit log entry contains name, address, DOB, gov_id, or private key bytes
    - **Validates: Requirements 5.8**


- [ ] 8. `corridor-sdk` — client library

  - [ ] 8.1 Implement `Note` type with `commitment()` and `nullifier()` methods
    - In `crates/corridor-sdk/src/note.rs`, implement `Note` from `crates/types`
    - `commitment(&self) -> [u8;32]` = `SHA-256(denomination.to_be_bytes() || salt || receiver_pk)`
    - `nullifier(&self) -> [u8;32]` = `SHA-256(salt || receiver_pk)`
    - Both methods must produce identical output for identical inputs across all runs (deterministic)
    - _Requirements: 1.3, 3.4_

  - [ ] 8.2 Implement Merkle path fetching from on-chain events
    - In `crates/corridor-sdk/src/merkle.rs`, implement `fetch_merkle_path(leaf_index: u32, rpc_url: &str) -> Result<MerklePath, SdkError>`
    - Fetch deposit events from Soroban RPC; extract sibling commitments from event stream
    - Reconstruct `siblings: [[u8;32];20]` and `indices: [bool;20]` from leaf position
    - _Requirements: 3.3_

  - [ ] 8.3 Implement `CorridorClient` with deposit, withdraw, fetch_merkle_path, get_current_root
    - In `crates/corridor-sdk/src/client.rs`, implement `CorridorClient`
    - `deposit`: validate amount, orchestrate proof generation via `zk-circuits`, submit to `on-ramp-service`
    - `withdraw`: fetch Merkle path, generate withdrawal + compliance proofs, submit to `off-ramp-service`
    - `fetch_merkle_path`: delegate to merkle module
    - `get_current_root`: call `shielded_pool.get_root()` via Soroban RPC
    - Wire `prove_deposit`, `prove_withdrawal`, `prove_compliance` from `zk-circuits` prover API
    - _Requirements: 1.4, 1.5, 4.2, 4.3_

  - [ ]* 8.4 Write property test for `Note` commitment/nullifier round-trip
    - **Property 2: Commitment well-formedness**
    - Use `proptest` with `denomination in (1..AML_THRESHOLD_STROOPS)`, arbitrary `salt`, `receiver_pk`
    - Assert `note.commitment() == SHA-256(denomination_be || salt || receiver_pk)` for all inputs
    - Assert `note.nullifier() == SHA-256(salt || receiver_pk)` for all inputs
    - **Property 1: Deposit note denomination preservation**
    - Assert that a `Note` constructed with `denomination = d` has `note.denomination == d` (no alteration)
    - **Validates: Requirements 1.2, 1.3, 3.2**

  - [ ]* 8.5 Write property test for invalid amount rejection at SDK layer
    - **Property 3: Invalid amount rejection**
    - Use `proptest` with `amount_stroops <= 0` (zero, negative values)
    - Assert `CorridorClient::deposit` returns `CorridorError::InvalidAmount` with zero side effects
    - No proof generation, no HTTP calls, no Soroban transactions emitted
    - **Validates: Requirements 1.10**


- [ ] 9. `on-ramp-service` — fiat deposit and shielded note minting

  - [ ] 9.1 Implement `DepositRequest` / `DepositResult` types and validation layer
    - In `services/on-ramp-service/src/types.rs`, define `DepositRequest { sender_kyc_credential_id, amount_stroops, receiver_shielded_pk }` and `DepositResult { commitment, leaf_index, note, tx_hash }`
    - Implement `validate_deposit_request`: reject `amount_stroops <= 0` → `CorridorError::InvalidAmount` immediately
    - _Requirements: 1.10, 8.1_

  - [ ] 9.2 Implement KYC credential fetch and expiry validation
    - Call Compliance Oracle `POST /oracle/credential` using `credential_id`
    - Deserialize `KycCredential`; check `credential.expires_at > epoch_now()` → else `CredentialExpired`
    - Check Ed25519 signature on credential → else `InvalidCredential`
    - _Requirements: 1.5, 10.3_

  - [ ] 9.3 Implement proof generation sequence (steps 4–8 of deposit flow)
    - Generate cryptographically random `salt: [u8;32]` via `OsRng`
    - Compute `commitment = SHA-256(amount_be || salt || receiver_pk)`
    - Call `prove_deposit(pk_deposit, amount, salt, receiver_pk)` → `(proof_d, inputs_d)`
    - Fetch current epoch from `GET /oracle/info`
    - Call `prove_compliance(pk_compliance, amount, credential, secret_key, epoch, vk_digest)` → `(proof_c, inputs_c)`
    - _Requirements: 1.3, 1.4, 1.5_

  - [ ] 9.4 Implement SEP-24 interactive deposit flow and atomicity with durable pending state
    - Initiate SEP-24 interactive deposit via anchor; persist `PendingDeposit { commitment, proofs, salt, receiver_pk, amount }` to SQLite durable store before anchor call
    - Await `fiat_confirmed` callback webhook
    - Build and submit Soroban tx: `shielded_pool.deposit(commitment, proof_d, inputs_d, proof_c, inputs_c, amount)`
    - On Soroban tx failure: call anchor `/transactions/{id}/refund` endpoint → return `DepositAtomicityFailure`
    - On tx success: remove pending state; return `DepositResult`
    - Memo, operation data, and account fields in the Soroban tx MUST NOT contain amount, sender, or receiver identity
    - _Requirements: 1.7, 1.8, 1.9_

  - [ ]* 9.5 Write integration tests for on-ramp service with mock anchor and mock Soroban
    - Use `wiremock` to mock US anchor SEP-24 endpoints and Soroban RPC
    - Test full happy path: validate → credential → prove → SEP-24 confirm → Soroban deposit → DepositResult
    - Test Soroban tx failure path: assert refund is triggered and `DepositAtomicityFailure` returned
    - Test `amount = 0`: assert `InvalidAmount` with no anchor calls made
    - Test expired credential: assert `CredentialExpired` with no proof generation
    - _Requirements: 1.6, 1.8, 1.9, 1.10_


- [ ] 10. `off-ramp-service` — shielded note redemption and MXN disbursement

  - [ ] 10.1 Implement `WithdrawalRequest` / `WithdrawalResult` types and field validation
    - In `services/off-ramp-service/src/types.rs`, define `WithdrawalRequest` and `WithdrawalResult` per design spec
    - Validate all fields non-empty; reject with `InvalidAmount` if `proof_bytes.len() != 192`
    - _Requirements: 4.1, 8.1_

  - [ ] 10.2 Implement dual-proof verification sequence via Soroban RPC
    - Call `verifier_contract.verify_proof(1, withdrawal_proof, [root, nullifier])` → `false`: return `ProofVerificationFailed`
    - Call `verifier_contract.verify_proof(2, compliance_proof, [vk_digest, epoch])` → `false`: return `ProofVerificationFailed`
    - Both verifications must pass before proceeding
    - _Requirements: 4.2, 4.3, 4.6_

  - [ ] 10.3 Implement atomic withdrawal Soroban transaction construction
    - Build single atomic Soroban tx: `shielded_pool.withdraw(nullifier, root, proof_w, proof_c, inputs, recipient)`
    - Map `NULLIFIER_ALREADY_SPENT` pool error → `CorridorError::NoteAlreadyRedeemed`
    - Memo and operation data MUST NOT contain redeemed amount, recipient identity, or Merkle path
    - _Requirements: 4.4, 4.7, 4.8_

  - [ ] 10.4 Implement SEP-24 MXN disbursement flow and 24-hour settlement timeout
    - On successful Soroban tx: initiate SEP-24 withdrawal with MX anchor (`recipient_anchor_account`)
    - Poll anchor status; on confirmation: emit settlement event `{ nullifier, timestamp }` and mark complete
    - Start 24-hour countdown from USDC transfer; on timeout: record `OfframpSettlementTimeout` — do NOT reverse on-chain tx
    - _Requirements: 4.5, 4.9, 4.10_

  - [ ]* 10.5 Write integration tests for off-ramp service with mock anchor and mock Soroban
    - Use `wiremock` to mock MX anchor SEP-24 endpoints and Soroban RPC responses
    - Test full happy path: dual-proof verify → Soroban withdraw → SEP-24 confirm → settlement event emitted
    - Test `NULLIFIER_ALREADY_SPENT` from pool: assert `NoteAlreadyRedeemed`
    - Test invalid withdrawal proof: assert `ProofVerificationFailed` with no Soroban tx submitted
    - Test anchor non-response for 24 h: assert `OfframpSettlementTimeout` with no on-chain reversal
    - _Requirements: 4.6, 4.7, 4.9, 4.10_

- [ ] 11. Checkpoint — off-chain services
  - Ensure all service unit and integration tests pass: `cargo test -p compliance-oracle -p corridor-sdk -p on-ramp-service -p off-ramp-service`
  - Ask the user if service interfaces or error mappings need adjustment before the end-to-end tests.


- [ ] 12. End-to-end integration tests

  - [ ] 12.1 Implement full deposit → withdrawal lifecycle test
    - Set up in-process testutils environment: deploy verifier-contract + shielded-pool; mock US and MX anchors with `wiremock`
    - Execute complete flow: on-ramp deposit (SEP-24 + Soroban) → corridor-sdk fetch Merkle path → off-ramp withdrawal (dual proof + SEP-24)
    - Assert final USDC balance of pool account, nullifier recorded, settlement event emitted with correct `{ nullifier, timestamp }`
    - _Requirements: 1.8, 2.7, 4.4, 6.1, 6.2_

  - [ ] 12.2 Implement privacy invariant assertions test
    - After a complete deposit + withdrawal cycle, scan all Soroban events emitted and all contract storage slots written
    - Assert no event payload contains `amount_stroops`, sender Stellar account, or receiver shielded pk in plaintext
    - Assert deposit events contain exactly `(commitment, leaf_index)` and withdrawal events exactly `(nullifier, leaf_index)`
    - Assert no storage slot in shielded-pool contains denomination or identity data
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

  - [ ] 12.3 Implement error path end-to-end tests
    - Test invalid proof submission: replace valid proof bytes with random bytes; assert `ProofVerificationFailed` at pool level
    - Test double-spend: submit same withdrawal twice; assert second returns `NullifierAlreadySpent`
    - Test expired credential: set `credential.expires_at = epoch - 1`; assert `CredentialExpired` before any Soroban tx
    - Test pool capacity: set `NextIndex = 2^20 - 1` in testutils; attempt one more deposit; assert `PoolCapacityExceeded`
    - _Requirements: 1.6, 2.6, 2.9, 5.7_

  - [ ]* 12.4 Write property test for AML threshold enforcement at Compliance_Circuit level
    - **Property 10: AML threshold enforcement**
    - Use `proptest` with `denomination >= AML_THRESHOLD_STROOPS` (100_000_000_000+)
    - Assert `prove_compliance` produces a proof that `verify_proof(2, ...)` returns `false`
    - Use `proptest` with `denomination in (1..AML_THRESHOLD_STROOPS)` + valid credential
    - Assert the proof is accepted by verifier
    - **Validates: Requirements 3.6**

  - [ ]* 12.5 Write property test for expired credential rejection
    - **Property 11: Expired credential rejection**
    - Use `proptest` to generate `(expires_at, epoch)` pairs where `expires_at < epoch`
    - Assert Compliance_Circuit proof is rejected by verifier for all such pairs
    - **Property 12: Credential revocation effectiveness**
    - After `revoke_credential`, assert all new Compliance_Circuit proofs using the revoked credential fail
    - **Validates: Requirements 5.3, 5.7**

  - [ ]* 12.6 Write property test for Withdrawal_Circuit soundness
    - **Property 9: Withdrawal circuit soundness**
    - For a valid Note in the tree: assert proof with correct witnesses is accepted
    - Use `proptest` to mutate one of: `denomination`, `salt`, `receiver_pk`, one sibling hash, one path index
    - Assert each mutation causes proof rejection
    - **Validates: Requirements 3.4**


- [ ] 13. Trusted setup tooling

  - [ ] 13.1 Implement trusted setup script for all three circuits
    - In `tools/trusted-setup/src/main.rs`, use `ark-groth16` `generate_random_parameters` (Groth16 phase-2 compatible)
    - Generate `ProvingKey` + `VerifyingKey` for `DepositCircuit`, `WithdrawalCircuit`, `ComplianceCircuit`
    - Serialize each key pair to files: `deposit.pk`, `deposit.vk`, `withdrawal.pk`, `withdrawal.vk`, `compliance.pk`, `compliance.vk`
    - Print SHA-256 digest of each `.vk` file to stdout for ceremony transcript inclusion
    - _Requirements: 7.1, 7.3_

  - [ ] 13.2 Implement VK digest computation and verification script
    - In `tools/trusted-setup/src/verify_vk.rs`, read stored `.vk` files and recompute `SHA-256(vk_bytes)` 
    - Compare against digests from the verifier-contract's initialization event
    - Exit non-zero if any digest mismatches; print pass/fail per circuit
    - _Requirements: 7.1, 7.4_

  - [ ] 13.3 Write README documenting the ceremony process
    - Document the trusted setup workflow: how to run `cargo run --bin trusted-setup`, how ceremony transcripts are produced, how to verify VK digests against deployed contract, and how Proving Keys are distributed to client software
    - Note that Proving Keys MUST NOT be stored in any Soroban contract or publicly accessible server
    - _Requirements: 7.1, 7.3_

- [ ] 14. Final checkpoint — full system
  - Run complete test suite: `cargo test --workspace`
  - Verify all 18 correctness properties have corresponding test coverage
  - Ask the user if any adjustments are needed before handing off for mainnet deployment planning.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; core correctness properties should be tested before mainnet deployment
- All 18 correctness properties from the design document have explicit test tasks referencing them
- Property tasks are placed immediately after the implementation they validate to catch errors early
- The FilledSubtree Merkle pattern keeps storage costs O(20) per insert regardless of tree size
- No Proving Key material is ever written to Soroban storage; keys live only on client machines
- SHA-256 is used consistently for all hashing (Soroban host function + `ark-crypto-primitives` gadget in-circuit)
- Error privacy rule: every `CorridorError` serialization must be audited to ensure it contains no amount, identity, Note preimage, or KYC_Credential field
- `proptest` strategies should use `prop::array::uniform32(0u8..)` for 32-byte arrays and `1_i64..AML_THRESHOLD_STROOPS` for valid denominations


## Task Dependency Graph

```json
{
  "waves": [
    {
      "id": 0,
      "tasks": ["1.1"]
    },
    {
      "id": 1,
      "tasks": ["1.2", "1.3"]
    },
    {
      "id": 2,
      "tasks": ["1.4", "2.1", "2.3", "2.5"]
    },
    {
      "id": 3,
      "tasks": ["2.2", "2.4", "2.6", "2.7"]
    },
    {
      "id": 4,
      "tasks": ["2.8", "2.9", "4.1"]
    },
    {
      "id": 5,
      "tasks": ["4.2", "4.3", "4.4"]
    },
    {
      "id": 6,
      "tasks": ["4.5", "4.6", "4.7", "5.1"]
    },
    {
      "id": 7,
      "tasks": ["5.2", "5.3"]
    },
    {
      "id": 8,
      "tasks": ["5.4", "5.5", "5.6"]
    },
    {
      "id": 9,
      "tasks": ["5.7", "5.8", "5.9", "5.10", "7.1"]
    },
    {
      "id": 10,
      "tasks": ["5.11", "7.2", "7.3", "7.4", "8.1"]
    },
    {
      "id": 11,
      "tasks": ["7.5", "7.6", "8.2", "8.3"]
    },
    {
      "id": 12,
      "tasks": ["8.4", "8.5", "9.1"]
    },
    {
      "id": 13,
      "tasks": ["9.2", "9.3"]
    },
    {
      "id": 14,
      "tasks": ["9.4", "10.1"]
    },
    {
      "id": 15,
      "tasks": ["9.5", "10.2", "10.3"]
    },
    {
      "id": 16,
      "tasks": ["10.4"]
    },
    {
      "id": 17,
      "tasks": ["10.5", "13.1"]
    },
    {
      "id": 18,
      "tasks": ["12.1", "13.2", "13.3"]
    },
    {
      "id": 19,
      "tasks": ["12.2", "12.3"]
    },
    {
      "id": 20,
      "tasks": ["12.4", "12.5", "12.6"]
    }
  ]
}
```
