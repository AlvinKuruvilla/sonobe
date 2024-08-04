use crate::frontend::FCircuit;
use crate::Error;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;

use super::merkle_gadget::MerkleTreeGadget;

#[derive(Clone, Copy, Debug)]
pub struct MerkleTreeCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for MerkleTreeCircuit<F> {
    type Params = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        4 // TODO: The final root hash will be of length 1
    }

    fn external_inputs_len(&self) -> usize {
        0 // TODO: We will take 4 inputs to create the Merkle tree
    }

    fn step_native(
        &self,
        _i: usize,
        z_i: Vec<F>,
        _external_inputs: Vec<F>,
    ) -> Result<Vec<F>, Error> {
        let root_hash = MerkleTreeGadget::create_root_hash_from_scalar_fields(z_i);
        // TODO: Return root_hash[0] only once
        Ok(vec![root_hash, root_hash, root_hash, root_hash])
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let root_hash = MerkleTreeGadget::create_root_hash(z_i)?;
        // TODO: Return root_hash[0].clone() only once
        Ok(vec![
            root_hash.clone(),
            root_hash.clone(),
            root_hash.clone(),
            root_hash.clone(),
        ])
    }
}
mod tests {
    use ark_bn254::Fr;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::UniformRand;

    use crate::{frontend::FCircuit, zcash::merkle_tree::MerkleTreeCircuit};

    #[test]
    fn simple() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Initialize the circuit
        let circuit = MerkleTreeCircuit::<Fr>::new(()).unwrap();

        // Generate random inputs
        let inputs: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();

        // Native computation
        let native_result = circuit.step_native(0, inputs.clone(), vec![]).unwrap();

        // Constraint system computation
        let input_vars = inputs
            .iter()
            .map(|input| FpVar::new_witness(cs.clone(), || Ok(input)).unwrap())
            .collect();
        let computed_result_var = circuit
            .generate_step_constraints(cs.clone(), 0, input_vars, vec![])
            .unwrap();

        // Check if both computations give the same result
        assert_eq!(computed_result_var.value().unwrap(), native_result);
        assert!(cs.is_satisfied().unwrap());

        println!("Merkle Tree circuit test passed!");
    }
}
