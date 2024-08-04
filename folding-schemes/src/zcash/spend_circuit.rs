use std::marker::PhantomData;

use ark_crypto_primitives::crh::{
    sha256::{
        constraints::{Sha256Gadget, UnitVar},
        Sha256,
    },
    CRHScheme, CRHSchemeGadget,
};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::{ToBytesGadget, ToConstraintFieldGadget};

use crate::{frontend::FCircuit, Error};

#[derive(Clone, Copy, Debug)]
pub struct SpendCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}
impl<F: PrimeField> FCircuit<F> for SpendCircuit<F> {
    type Params = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        // Three inputs: the original value, split value1, split value 2
        3
    }

    fn external_inputs_len(&self) -> usize {
        0
    }

    fn step_native(
        &self,
        i: usize,
        z_i: Vec<F>,
        external_inputs: Vec<F>, // inputs that are not part of the state
    ) -> Result<Vec<F>, Error> {
        let bytes: Vec<u8> = z_i[0].into_bigint().to_bytes_le();

        // Hash the combined byte array using SHA-256
        let out_bytes: Vec<u8> = Sha256::evaluate(&(), bytes).unwrap();
        let out1: Vec<F> = out_bytes.to_field_elements().unwrap();
        let bytes2: Vec<u8> = z_i[1].into_bigint().to_bytes_le();
        let out_bytes2: Vec<u8> = Sha256::evaluate(&(), bytes2).unwrap();
        let out2: Vec<F> = out_bytes2.to_field_elements().unwrap();
        Ok(vec![out1[0], out2[0]])
    }

    fn generate_step_constraints(
        &self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<ark_r1cs_std::fields::fp::FpVar<F>>,
        external_inputs: Vec<ark_r1cs_std::fields::fp::FpVar<F>>, // inputs that are not part of the state
    ) -> Result<Vec<ark_r1cs_std::fields::fp::FpVar<F>>, ark_relations::r1cs::SynthesisError> {
        let mut input_bytes = vec![];
        input_bytes.extend_from_slice(&z_i[0].to_bytes()?);

        let unit_var = UnitVar::default();
        let out_bytes = Sha256Gadget::evaluate(&unit_var, &input_bytes)?;
        let out = out_bytes.0.to_constraint_field()?;

        let mut input_bytes2 = vec![];
        input_bytes2.extend_from_slice(&z_i[1].to_bytes()?);

        let out_bytes2 = Sha256Gadget::evaluate(&unit_var, &input_bytes2)?;
        let out2 = out_bytes2.0.to_constraint_field()?;

        Ok(vec![out[0].clone(), out2[0].clone()])
    }
}
