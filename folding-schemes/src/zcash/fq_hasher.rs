// Two main insights related to circuit design:
// 1. Seems like Fr elements will work for circuit input (z_0)
// 2. The usize of state_len must be the same as the length of z_0 and must also be the same length as the number of
//     elements returned in step_native and I think generate_step_constraints but I'm not certain about that
use ark_crypto_primitives::crh::{
    sha256::{
        constraints::{Sha256Gadget, UnitVar},
        Sha256,
    },
    CRHScheme, CRHSchemeGadget,
};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::ToBytesGadget;
use ark_r1cs_std::{fields::fp::FpVar, ToConstraintFieldGadget};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;

use crate::{frontend::FCircuit, Error};
#[derive(Clone, Copy, Debug)]
pub struct HashTwoFqCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for HashTwoFqCircuit<F> {
    type Params = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        2 // This ensures the state length is always 2
    }

    fn external_inputs_len(&self) -> usize {
        0
    }

    fn step_native(
        &self,
        _i: usize,
        z_i: Vec<F>,
        _external_inputs: Vec<F>,
    ) -> Result<Vec<F>, Error> {
        // Combine the two input values into a single byte array
        // assert_eq!(z_i.len(), 2);
        let mut bytes = z_i[0].into_bigint().to_bytes_le();
        bytes.extend(z_i[1].into_bigint().to_bytes_le());

        // Hash the combined byte array using SHA-256
        let out_bytes = Sha256::evaluate(&(), bytes).unwrap();
        let out: Vec<F> = out_bytes.to_field_elements().unwrap();

        // Return the hashed value
        // NOTE: The only reason to return the same value  as 2 elements in the vector is to satisfy the state length
        Ok(vec![out[0], out[0]])
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Convert the two input values to bytes and combine them
        let mut input_bytes = vec![];
        input_bytes.extend_from_slice(&z_i[0].to_bytes()?);
        // input_bytes.extend_from_slice(&z_i[1].to_bytes()?);

        // Hash the combined byte array using the SHA-256 gadget
        let unit_var = UnitVar::default();
        let out_bytes = Sha256Gadget::evaluate(&unit_var, &input_bytes)?;
        let out = out_bytes.0.to_constraint_field()?;

        // Return the hashed value
        Ok(vec![out[0].clone()])
    }
}
