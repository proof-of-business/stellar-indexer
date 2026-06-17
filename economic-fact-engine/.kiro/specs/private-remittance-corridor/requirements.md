# Requirements Document

## Private Cross-Border Remittance Corridor

---

## Introduction

The Private Remittance Corridor is a new feature layer within Project Blueprint that enables end-to-end confidential cross-border money transfers on Stellar's payment rails. The MVP covers a single USD→MXN corridor: a sender in the United States deposits fiat USD with a licensed on-ramp anchor, the transferred value traverses the network as a cryptographic shielded commitment (so no on-chain observer can determine the amount, sender, or receiver), and a recipient in Mexico redeems a shielded note with a licensed off-ramp anchor to receive local MXN.

Privacy is achieved via a Merkle-tree-based shielded pool deployed as a Soroban smart contract on Stellar. Zero-knowledge proofs (Groth16 over BLS12-381, using CAP-0059 on Stellar mainnet) provide both privacy and compliance attestation at the corridor edges. At deposit and withdrawal, ZK compliance proofs certify that the transfer amount is below the USD 10,000 AML reporting threshold and that both parties hold valid KYC credentials — without revealing the actual amount or identity to any third party.

This feature sits above the existing Economic Fact Engine (Layer 2) and uses Stellar/Soroban as its settlement substrate. All shielded asset transfers use USDC on Stellar. Fiat on/off-ramp integration uses SEP-6/SEP-24 anchor protocols.

---

## Glossary

- **Corridor**: The end-to-end remittance path from a USD fiat on-ramp (US) to an MXN fiat off-ramp (Mexico), implemented as a single shielded transfer over Stellar.
- **On_Ramp_Module**: The software component that integrates with a Stellar SEP-6/SEP-24 anchor to accept fiat USD, mint a shielded Note, and deposit that Note into the Shielded_Pool.
- **Off_Ramp_Module**: The software component that accepts a valid ZK withdrawal proof, verifies it via the Verifier_Contract, releases USDC to the off-ramp anchor, and triggers an MXN fiat payout.
- **Shielded_Pool**: A Soroban smart contract maintaining a Merkle-tree-based commitment pool. Users deposit Note commitments and withdraw using ZK proofs; amounts are never exposed on-chain.
- **Note**: A cryptographic representation of a specific USDC amount in the Shielded_Pool, comprising a commitment (a Pedersen or SHA-256 hash over BLS12-381 of the amount, a salt, and the owner's public key), a denomination in USDC stroops, and a salt for hiding.
- **Nullifier**: A unique, unlinkable value derived from a Note that is published on-chain at withdrawal time to prevent double-spending, without revealing which Note was spent.
- **Commitment**: The on-chain hash of a Note's secret preimage. Once a Note is deposited, only its Commitment is recorded in the Merkle tree.
- **Merkle_Root**: The root hash of the incremental Merkle tree maintained by the Shielded_Pool, representing the current state of all deposited commitments.
- **ZK_Proof_Layer**: The collection of Groth16 proving and verification circuits used by the system: Deposit_Circuit, Withdrawal_Circuit, and Compliance_Circuit.
- **Deposit_Circuit**: The ZK circuit that proves a Note Commitment is well-formed (i.e., the prover knows the Note's secret preimage).
- **Withdrawal_Circuit**: The ZK circuit that proves the prover knows the preimage of a Commitment in the current Merkle tree and that the corresponding Nullifier has not been spent.
- **Compliance_Circuit**: The ZK circuit that proves (a) the transfer amount is strictly less than USD 10,000 expressed in USDC stroops, and (b) the prover holds a valid KYC_Credential issued by the Compliance_Oracle — without revealing the amount or the identity.
- **Compliance_Oracle**: The off-chain service that issues ZK-verifiable KYC credentials to pre-verified users. Each credential commits to the user's identity attributes and is signed under the Oracle's verification key.
- **KYC_Credential**: A signed attestation issued by the Compliance_Oracle that certifies a user has passed identity verification. The credential is referenced inside a Compliance_Circuit proof without revealing identity details.
- **Verifier_Contract**: A Soroban smart contract that verifies Groth16 proofs on-chain using CAP-0059 host functions. Shared by the Shielded_Pool (for Withdrawal_Circuit proofs) and the Off_Ramp_Module (for Compliance_Circuit proofs).
- **Proving_Key**: The Groth16 proving key generated from a trusted setup ceremony for a specific circuit. Used client-side to generate proofs.
- **Verification_Key**: The Groth16 verification key derived from a trusted setup ceremony for a specific circuit. Stored in the Verifier_Contract.
- **Stroop**: The smallest unit of a Stellar asset. 1 USDC = 10,000,000 stroops. All amounts are represented internally as i64 stroops.
- **USDC**: USD Coin on Stellar, identified by asset code `USDC` and the canonical issuer `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`.
- **SEP_6**: Stellar Ecosystem Proposal 6 — the non-interactive anchor protocol for programmatic fiat deposit and withdrawal.
- **SEP_24**: Stellar Ecosystem Proposal 24 — the interactive anchor protocol for fiat deposit and withdrawal via a hosted web flow.
- **AML_Threshold**: The USD 10,000 regulatory reporting threshold. Transfers below this value do not require a Currency Transaction Report (CTR). The MVP enforces this bound via the Compliance_Circuit.
- **CTR**: Currency Transaction Report — a regulatory filing required in the US for cash transactions at or above USD 10,000.
- **Regulator_Proof**: A Compliance_Circuit proof together with its public inputs, which a regulator can verify independently to confirm the transfer was compliant, without learning the amount or identity.
- **BLS12-381**: The elliptic curve pairing used for Groth16 proofs, available on Stellar mainnet via CAP-0059.
- **Trusted_Setup**: The multi-party computation ceremony that generates a Proving_Key and Verification_Key for each ZK circuit. The ceremony output must be available before the system can generate or verify proofs.
- **Merkle_Path**: The sibling hash values along the path from a leaf node to the Merkle_Root, used by the Withdrawal_Circuit to prove membership of a Commitment in the tree.
- **Deposit_Request**: The input to the On_Ramp_Module containing the sender's KYC_Credential reference, the desired USDC amount, and the receiver's shielded public key.
- **Withdrawal_Request**: The input to the Off_Ramp_Module containing a Withdrawal_Circuit ZK proof, a Compliance_Circuit ZK proof, the Nullifier, the Merkle_Root, and the recipient's off-ramp anchor details.

---

## Requirements

---

### Requirement 1: Fiat On-Ramp — Accept Fiat Deposit and Mint Shielded Note

**User Story:** As a sender in the United States, I want to deposit fiat USD with a licensed on-ramp provider and receive a shielded Note, so that I can initiate a private cross-border transfer without revealing my amount or identity to on-chain observers.

#### Acceptance Criteria

1. THE On_Ramp_Module SHALL integrate with a SEP-6 or SEP-24 compliant Stellar anchor to accept USD fiat deposits from pre-KYC-verified senders.
2. WHEN a sender submits a Deposit_Request with a valid KYC_Credential reference, a USDC amount greater than zero stroops, and a receiver's shielded public key, THE On_Ramp_Module SHALL mint exactly one Note whose denomination equals the deposited USDC amount expressed in stroops.
3. WHEN a Note is minted, THE On_Ramp_Module SHALL compute a Commitment by hashing the Note's denomination, salt, and the receiver's shielded public key using SHA-256 or Pedersen hash over BLS12-381, and SHALL submit that Commitment to the Shielded_Pool for insertion into the Merkle tree.
4. THE On_Ramp_Module SHALL generate a Deposit_Circuit ZK proof attesting that the Commitment is well-formed before submitting it to the Shielded_Pool.
5. THE On_Ramp_Module SHALL generate a Compliance_Circuit ZK proof attesting that the deposited amount is strictly less than the AML_Threshold (USD 10,000, expressed as 100,000,000,000 stroops) and that the sender holds a valid KYC_Credential.
6. WHEN the Deposit_Circuit proof or the Compliance_Circuit proof fails to verify, THE On_Ramp_Module SHALL abort the deposit, release no USDC to the Shielded_Pool, and return a structured error with error code `PROOF_VERIFICATION_FAILED`.
7. THE On_Ramp_Module SHALL NOT record the deposited amount, the sender's identity, or the receiver's public key in any Stellar transaction's memo, operation data, or account field.
8. WHEN the SEP-6/SEP-24 anchor confirms the fiat deposit, THE On_Ramp_Module SHALL complete the on-chain deposit within the same Soroban transaction that inserts the Commitment into the Shielded_Pool; the USDC transfer to the pool and the Commitment insertion SHALL be atomic.
9. IF the Soroban transaction that inserts the Commitment fails after the fiat deposit has been confirmed, THEN THE On_Ramp_Module SHALL initiate a refund of the full USDC amount to the sender's anchor account and return a structured error with error code `DEPOSIT_ATOMICITY_FAILURE`.
10. WHEN a Deposit_Request contains a USDC amount of zero stroops or a negative value, THE On_Ramp_Module SHALL reject the request without interacting with the anchor and return a structured error with error code `INVALID_AMOUNT`.

---

### Requirement 2: Shielded Pool — Merkle-Tree Commitment Pool on Soroban

**User Story:** As the system, I want a Soroban-based shielded commitment pool that records Note commitments without revealing amounts or identities, so that the corridor achieves on-chain privacy throughout the transfer.

#### Acceptance Criteria

1. THE Shielded_Pool SHALL be implemented as a Soroban smart contract that maintains an incremental Merkle tree of Commitments, where each leaf is a Commitment and the tree depth is fixed at 20 levels (supporting up to 2^20 = 1,048,576 Commitments).
2. WHEN a Commitment is submitted for deposit by the On_Ramp_Module, THE Shielded_Pool SHALL insert the Commitment as a new leaf in the incremental Merkle tree and update the Merkle_Root.
3. THE Shielded_Pool SHALL store only Commitments and Nullifiers on-chain; the underlying Note denomination, sender identity, and receiver identity SHALL NOT be stored in any Soroban contract storage slot.
4. WHEN a Commitment is inserted, THE Shielded_Pool SHALL emit a Soroban event containing the Commitment value and the leaf index, and SHALL NOT include any amount or identity information in the event payload.
5. WHEN a withdrawal is attempted, THE Shielded_Pool SHALL verify the submitted Withdrawal_Circuit ZK proof via the Verifier_Contract before releasing any USDC.
6. WHEN a Withdrawal_Circuit proof is verified, THE Shielded_Pool SHALL check that the submitted Nullifier has not previously been recorded; IF the Nullifier has already been recorded, THEN THE Shielded_Pool SHALL reject the withdrawal and return error code `NULLIFIER_ALREADY_SPENT`.
7. WHEN a withdrawal succeeds, THE Shielded_Pool SHALL record the Nullifier on-chain to prevent double-spending and SHALL transfer the corresponding USDC amount to the Off_Ramp_Module's designated Stellar account.
8. THE Shielded_Pool SHALL maintain the Merkle_Root as a public contract state variable that any caller can read, enabling provers to construct Merkle_Path witnesses off-chain.
9. WHEN the Merkle tree is full (all 2^20 leaves are occupied), THE Shielded_Pool SHALL reject new deposits and return error code `POOL_CAPACITY_EXCEEDED`.
10. THE Shielded_Pool SHALL reject any direct USDC transfer that is not accompanied by a valid Deposit_Circuit ZK proof; unshielded USDC deposits SHALL return error code `UNSHIELDED_DEPOSIT_REJECTED`.

---

### Requirement 3: ZK Proof Layer — Deposit, Withdrawal, and Compliance Circuits

**User Story:** As the privacy and compliance layer, I want well-defined ZK circuits for deposit validity, withdrawal validity, and compliance attestation, so that the system can prove correctness and regulatory compliance without revealing private data.

#### Acceptance Criteria

1. THE ZK_Proof_Layer SHALL implement the Deposit_Circuit as a Groth16 circuit over BLS12-381 with the following public inputs: the Commitment; and the following private inputs (witnesses): the Note denomination in stroops, the salt, and the receiver's shielded public key.
2. WHEN a Deposit_Circuit proof is generated, THE Deposit_Circuit SHALL enforce the constraint that `Commitment == Hash(denomination || salt || receiver_public_key)` using SHA-256 or Pedersen hash over BLS12-381.
3. THE ZK_Proof_Layer SHALL implement the Withdrawal_Circuit as a Groth16 circuit over BLS12-381 with the following public inputs: the Merkle_Root and the Nullifier; and the following private inputs: the Note denomination in stroops, the salt, the receiver's shielded public key, and the Merkle_Path.
4. WHEN a Withdrawal_Circuit proof is generated, THE Withdrawal_Circuit SHALL enforce: (a) `Commitment == Hash(denomination || salt || receiver_public_key)`, (b) the Commitment is a leaf reachable from the Merkle_Root via the Merkle_Path, and (c) `Nullifier == Hash(salt || receiver_public_key)` using the same hash function as the Deposit_Circuit.
5. THE ZK_Proof_Layer SHALL implement the Compliance_Circuit as a Groth16 circuit over BLS12-381 with the following public inputs: the Compliance_Oracle's verification key digest and an epoch timestamp; and the following private inputs: the Note denomination in stroops, the KYC_Credential signed by the Compliance_Oracle, and the credential holder's secret key.
6. WHEN a Compliance_Circuit proof is generated, THE Compliance_Circuit SHALL enforce: (a) `denomination < AML_Threshold` (strictly less than 100,000,000,000 stroops, i.e. USD 10,000 at 7 decimal places), and (b) the KYC_Credential signature verifies under the Compliance_Oracle's public key and has not expired at the epoch timestamp.
7. THE Verifier_Contract SHALL verify Groth16 proofs on-chain using CAP-0059 Soroban host functions and SHALL expose a single entry point `verify_proof(circuit_id, proof_bytes, public_inputs) -> bool`.
8. WHEN a proof submitted to the Verifier_Contract does not satisfy the circuit constraints, THE Verifier_Contract SHALL return `false` and SHALL NOT revert or panic; the calling contract is responsible for treating `false` as a rejection.
9. THE Proving_Key and Verification_Key for each circuit (Deposit_Circuit, Withdrawal_Circuit, Compliance_Circuit) SHALL be derived from a Trusted_Setup ceremony; the Verification_Key for each circuit SHALL be stored immutably in the Verifier_Contract at deployment time.
10. THE ZK_Proof_Layer SHALL generate proofs client-side (off-chain); no Proving_Key material SHALL be transmitted to the Soroban contract or stored on-chain.
11. WHEN BN254 + Poseidon (CAP-0074/CAP-0075) become available on Stellar mainnet, THE Verifier_Contract architecture SHALL support upgrading to BN254-based circuits without redeploying the Shielded_Pool contract; the `circuit_id` parameter in `verify_proof` SHALL serve as the extension point for this upgrade path.

---

### Requirement 4: Fiat Off-Ramp — Redeem Shielded Note and Disburse MXN

**User Story:** As a recipient in Mexico, I want to redeem a shielded Note with a licensed off-ramp provider and receive MXN in my local bank account, so that I can access the transferred value without any on-chain observer learning the amount or my identity.

#### Acceptance Criteria

1. THE Off_Ramp_Module SHALL accept a Withdrawal_Request containing a Withdrawal_Circuit ZK proof, a Compliance_Circuit ZK proof, a Nullifier, a Merkle_Root, and the recipient's SEP-6/SEP-24 off-ramp anchor account details.
2. WHEN a Withdrawal_Request is received, THE Off_Ramp_Module SHALL submit the Withdrawal_Circuit proof to the Verifier_Contract and SHALL proceed only if the Verifier_Contract returns `true`.
3. WHEN a Withdrawal_Request is received, THE Off_Ramp_Module SHALL submit the Compliance_Circuit proof to the Verifier_Contract and SHALL proceed only if the Verifier_Contract returns `true` for the compliance proof.
4. WHEN both the Withdrawal_Circuit proof and the Compliance_Circuit proof are verified, THE Off_Ramp_Module SHALL invoke the Shielded_Pool's withdrawal entry point in a single atomic Soroban transaction that records the Nullifier and transfers USDC to the off-ramp anchor's designated Stellar account.
5. THE Off_Ramp_Module SHALL instruct the off-ramp anchor to convert the received USDC to MXN and disburse to the recipient's registered bank account using the SEP-6 or SEP-24 protocol; the MXN FX conversion is the anchor's responsibility and is outside the Soroban contract boundary.
6. IF the Verifier_Contract returns `false` for either the Withdrawal_Circuit proof or the Compliance_Circuit proof, THEN THE Off_Ramp_Module SHALL reject the Withdrawal_Request and return error code `PROOF_VERIFICATION_FAILED` without transferring any USDC.
7. IF the Shielded_Pool returns `NULLIFIER_ALREADY_SPENT`, THEN THE Off_Ramp_Module SHALL reject the Withdrawal_Request and return error code `NOTE_ALREADY_REDEEMED` to the caller.
8. THE Off_Ramp_Module SHALL NOT record the redeemed USDC amount, the recipient's identity, or the Merkle_Path in any Stellar transaction memo, operation data, or anchor API field beyond what the SEP protocol requires for settlement.
9. WHEN the off-ramp anchor confirms MXN disbursement, THE Off_Ramp_Module SHALL mark the Withdrawal_Request as complete and SHALL emit a settlement event containing only the Nullifier and a timestamp.
10. IF the off-ramp anchor fails to confirm MXN disbursement within 24 hours of USDC transfer, THEN THE Off_Ramp_Module SHALL surface an error code `OFFRAMP_SETTLEMENT_TIMEOUT` and SHALL NOT attempt to reverse the on-chain USDC transfer; manual reconciliation is required.

---

### Requirement 5: Compliance Oracle — Issue and Verify ZK-Verifiable KYC Credentials

**User Story:** As a compliance officer, I want a Compliance Oracle that issues ZK-verifiable KYC credentials to pre-verified users, so that the system can prove regulatory compliance at the corridor edges without exposing user identity to any party other than the oracle.

#### Acceptance Criteria

1. THE Compliance_Oracle SHALL issue a KYC_Credential to each pre-verified user containing: a credential identifier, the oracle's epoch timestamp, a credential expiry timestamp, and a signature over the commitment to the user's identity attributes under the Compliance_Oracle's private key.
2. THE Compliance_Oracle SHALL NOT embed the user's name, address, date of birth, or government ID number in the on-chain KYC_Credential; identity attributes SHALL be committed to via a hash and the preimage SHALL remain exclusively with the user and the Compliance_Oracle.
3. WHEN a user's KYC verification status changes (e.g., fails re-verification or is sanctioned), THE Compliance_Oracle SHALL issue an updated credential with a past expiry timestamp, causing all future Compliance_Circuit proofs referencing the user's credential to fail the expiry check.
4. THE Compliance_Oracle SHALL expose a public endpoint that returns the current Verification_Key digest and the current epoch timestamp, so that Compliance_Circuit provers can obtain the required public inputs without querying the Soroban contract.
5. WHEN a Compliance_Circuit proof is presented to a regulator, THE regulator SHALL be able to verify the proof using only the Compliance_Oracle's public verification key, the public inputs (Verification_Key digest and epoch timestamp), and the Groth16 verification algorithm — without access to the user's identity, KYC_Credential content, or transfer amount.
6. THE Compliance_Oracle SHALL rotate its signing key at most once per calendar year; WHEN a key rotation occurs, THE Compliance_Oracle SHALL continue to accept proofs referencing the previous key for a transition period of 90 days.
7. WHEN a KYC_Credential's expiry timestamp has passed at the time of proof generation, THE Compliance_Circuit SHALL produce a proof that the Verifier_Contract will reject, preventing expired-credential holders from completing transfers.
8. THE Compliance_Oracle SHALL maintain an append-only audit log recording the credential identifier, the issuance timestamp, and the expiry timestamp for every KYC_Credential issued; no identity attributes or private key material SHALL appear in the audit log.

---

### Requirement 6: End-to-End Transfer Privacy

**User Story:** As a system operator, I want the full transfer path — from deposit through the shielded pool to withdrawal — to reveal no amount, sender identity, or receiver identity on-chain, so that the corridor satisfies the privacy requirements of both users and applicable data protection regulations.

#### Acceptance Criteria

1. THE Corridor SHALL ensure that no Stellar transaction, Soroban contract storage slot, event payload, or ledger entry contains the transfer amount in plaintext at any point during the deposit-to-withdrawal lifecycle.
2. THE Corridor SHALL ensure that no Stellar transaction, Soroban contract storage slot, event payload, or ledger entry links the sender's Stellar account to the receiver's Stellar account or off-ramp destination.
3. WHEN the Shielded_Pool emits a deposit event, THE event payload SHALL contain only the Commitment and the leaf index; it SHALL NOT contain the Note denomination, the sender's account address, or the receiver's shielded public key.
4. WHEN the Shielded_Pool emits a withdrawal event, THE event payload SHALL contain only the Nullifier and the leaf index; it SHALL NOT contain the redeemed amount or any account identifier.
5. THE Corridor SHALL ensure that a withdrawal transaction cannot be correlated with its corresponding deposit transaction by any on-chain observer who does not possess the Note's secret preimage (denomination, salt, and receiver public key).
6. WHILE a Note is unspent in the Shielded_Pool, THE Shielded_Pool SHALL make the Nullifier for that Note computationally indistinguishable from a random value to any party who does not hold the Note's salt and receiver public key.

---

### Requirement 7: Trusted Setup and Key Management

**User Story:** As a system operator, I want the ZK circuit keys to be generated via a verifiable Trusted_Setup ceremony and stored with appropriate access controls, so that no single party can forge proofs or compromise the system's cryptographic security.

#### Acceptance Criteria

1. THE Trusted_Setup SHALL be executed as a multi-party computation ceremony for each of the three circuits (Deposit_Circuit, Withdrawal_Circuit, Compliance_Circuit) before the system is deployed to mainnet; the ceremony transcript SHALL be published for public verification.
2. THE Verification_Key for each circuit SHALL be stored in the Verifier_Contract as an immutable contract data entry at deployment time and SHALL NOT be modifiable after deployment without redeploying the Verifier_Contract.
3. THE Proving_Key for each circuit SHALL be distributed to client-side software only; Proving_Keys SHALL NOT be stored in any Soroban contract, Stellar account, or publicly accessible server-side storage.
4. WHEN the Verifier_Contract is deployed, THE deploying transaction SHALL emit an initialization event containing the SHA-256 digest of each Verification_Key, enabling independent parties to verify the keys match the Trusted_Setup ceremony output.
5. IF a cryptographic vulnerability is discovered in a deployed circuit's Trusted_Setup or in the BLS12-381 Groth16 implementation, THEN THE Verifier_Contract SHALL support an authorized key-rotation mechanism gated by a multi-signature Stellar account (minimum 3-of-5 signers) to replace the Verification_Key for the affected circuit.

---

### Requirement 8: Error Handling and Structured Errors

**User Story:** As an integrating developer, I want all error conditions across the On_Ramp_Module, Off_Ramp_Module, Shielded_Pool, and Verifier_Contract to return structured, machine-readable error codes, so that I can handle failures programmatically.

#### Acceptance Criteria

1. THE Corridor SHALL define the following error codes covering all failure conditions: `PROOF_VERIFICATION_FAILED`, `NULLIFIER_ALREADY_SPENT`, `NOTE_ALREADY_REDEEMED`, `DEPOSIT_ATOMICITY_FAILURE`, `UNSHIELDED_DEPOSIT_REJECTED`, `POOL_CAPACITY_EXCEEDED`, `INVALID_AMOUNT`, `INVALID_CREDENTIAL`, `CREDENTIAL_EXPIRED`, `OFFRAMP_SETTLEMENT_TIMEOUT`, and `ANCHOR_INTEGRATION_FAILURE`.
2. WHEN an error occurs in any Soroban contract, THE contract SHALL return a structured Soroban contract error value containing a distinct error code; contracts SHALL NOT panic or abort with untyped errors.
3. THE Shielded_Pool, Verifier_Contract, On_Ramp_Module, and Off_Ramp_Module SHALL NOT include the user's identity, the transfer amount, the Note preimage, or the KYC_Credential content in any error message or error event.
4. EVERY failure condition across all Corridor components SHALL map to exactly one of the defined error codes; no undocumented or untyped errors SHALL be surfaced to callers.

---

### Requirement 9: Serialization and Proof Encoding Round-Trip

**User Story:** As a client-side prover, I want proof bytes and public inputs to be serialized and deserialized without loss, so that proofs generated off-chain can be transmitted and verified on-chain without corruption.

#### Acceptance Criteria

1. THE ZK_Proof_Layer SHALL serialize Groth16 proof objects to a canonical byte encoding compatible with the CAP-0059 host function's expected input format.
2. FOR ALL valid Groth16 proof objects for any of the three circuits, serializing the proof to bytes and deserializing it back SHALL produce a proof that the Verifier_Contract accepts with the same public inputs (round-trip property).
3. THE ZK_Proof_Layer SHALL serialize public inputs as a length-prefixed array of BLS12-381 scalar field elements in big-endian byte order, consistent with the CAP-0059 encoding specification.
4. WHEN a proof byte string is malformed or does not decode to a valid Groth16 proof structure, THE Verifier_Contract SHALL return `false` rather than panic or revert.
5. THE Note's denomination, salt, and commitment SHALL each be serialized as big-endian 256-bit integers when passed as circuit witnesses or public inputs; FOR ALL valid Note values, serializing then deserializing SHALL recover the original values exactly (round-trip property).

---

### Requirement 10: MVP Scope Constraints

**User Story:** As a product manager, I want the MVP to be scoped to a single USD→MXN corridor with a single asset and pre-verified users only, so that we can validate the core privacy and compliance mechanics before expanding to multiple corridors or assets.

#### Acceptance Criteria

1. THE Corridor SHALL support exactly one corridor in the MVP: USD fiat on-ramp (United States) to MXN fiat off-ramp (Mexico); multi-corridor routing is out of scope.
2. THE Shielded_Pool SHALL support exactly one shielded asset in the MVP: USDC on Stellar identified by asset code `USDC` and issuer `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`; multi-asset pools are out of scope.
3. THE On_Ramp_Module SHALL accept Deposit_Requests only from users who already hold a valid, non-expired KYC_Credential issued by the Compliance_Oracle; real-time KYC enrollment is out of scope for the MVP.
4. THE Compliance_Circuit SHALL enforce the AML_Threshold at USD 10,000 (100,000,000,000 stroops) only; tiered thresholds and currency-adjusted limits are out of scope for the MVP.
5. THE Corridor SHALL NOT perform on-chain FX conversion via the Stellar DEX in the MVP; the off-ramp anchor is solely responsible for converting USDC to MXN at the prevailing exchange rate.
6. THE Corridor SHALL NOT implement sanctions screening ZK proofs in the MVP; sanctions compliance remains an off-chain responsibility of the on-ramp and off-ramp anchors.
