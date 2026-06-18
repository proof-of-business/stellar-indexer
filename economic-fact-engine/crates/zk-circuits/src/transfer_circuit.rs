use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Placeholder circuit that proves knowledge of a valid transfer amount.
pub struct TransferCircuit<F: Field> {
    /// Private: the transfer amount.
    pub amount: Option<F>,
    /// Public: the commitment to the amount.
    pub commitment: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for TransferCircuit<F> {
    fn generate_constraints(self, _cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // TODO: implement actual R1CS constraints.
        Ok(())
    }
}
