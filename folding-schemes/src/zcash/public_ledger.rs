use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHGadget, CRHParametersVar},
            CRH,
        },
        CRHScheme, CRHSchemeGadget,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::SynthesisError;

use crate::{frontend::FCircuit, Error};
#[derive(Clone, Debug)]
pub struct PublicLedgerCircuit<F: PrimeField>
where
    F: Absorb,
{
    _f: PhantomData<F>,
    poseidon_config: PoseidonConfig<F>,
}
impl<F: PrimeField> FCircuit<F> for PublicLedgerCircuit<F>
where
    F: Absorb,
{
    type Params = PoseidonConfig<F>;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            _f: PhantomData,
            poseidon_config: _params,
        })
    }

    fn state_len(&self) -> usize {
        // One public input: the poseidon hash of the elements of vector T
        2
    }

    fn external_inputs_len(&self) -> usize {
        // The raw T vector which should be secret
        // The size of T should match whatever number is here
        6
    }
    fn step_native(
        &self,
        i: usize,
        z_i: Vec<F>,
        external_inputs: Vec<F>, // inputs that are not part of the state
    ) -> Result<Vec<F>, Error> {
        let mut inputs: Vec<F> = [].to_vec();
        let mid = external_inputs.len() / 2;
        let (first_half, second_half) = external_inputs.split_at(mid);
        let first_half_vec: Vec<F> = first_half.to_vec();
        let second_half_vec: Vec<F> = second_half.to_vec();

        for ex_input in first_half_vec {
            inputs.push(ex_input)
        }
        let h = CRH::<F>::evaluate(&self.poseidon_config, inputs).unwrap();

        let mut inputs: Vec<F> = [].to_vec();
        for ex_input in second_half_vec {
            inputs.push(ex_input)
        }
        let h1 = CRH::<F>::evaluate(&self.poseidon_config, inputs).unwrap();

        // I don't think we can do multiple vectors of external inputs so maybe we just allocate one big vector and
        //  half is for spend keys and the other for transaction hashes
        assert_eq!(z_i[0], h);
        assert_eq!(z_i[1], h1);
        Ok(vec![h, h1])
    }
    fn generate_step_constraints(
        &self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<ark_r1cs_std::fields::fp::FpVar<F>>,
        external_inputs: Vec<ark_r1cs_std::fields::fp::FpVar<F>>, // inputs that are not part of the state
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let crh_params =
            CRHParametersVar::<F>::new_constant(cs.clone(), self.poseidon_config.clone())?;
        let spend_keys = &external_inputs[0];
        let transaction_hashes = &external_inputs[1];
        let h: FpVar<F> = CRHGadget::<F>::evaluate(&crh_params, &[spend_keys.to_owned()])?;
        let h1 = CRHGadget::<F>::evaluate(&crh_params, &[transaction_hashes.to_owned()])?;

        Ok(vec![h, h1])
    }
}
