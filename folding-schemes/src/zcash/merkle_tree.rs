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
        Ok(vec![root_hash, root_hash, root_hash, root_hash])
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let root_hash = MerkleTreeGadget::create_root_hash(z_i, cs);
        Ok(vec![
            root_hash.clone(),
            root_hash.clone(),
            root_hash.clone(),
            root_hash.clone(),
        ])
    }
}
