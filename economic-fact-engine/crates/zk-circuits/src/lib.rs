/// ZK circuit definitions for the private remittance corridor.
///
/// Circuits prove that a transfer satisfies compliance constraints
/// without revealing the sender, recipient, or amount on-chain.
pub mod transfer_circuit;
pub mod deposit;
pub mod withdrawal;
pub mod compliance;
pub mod prover;
