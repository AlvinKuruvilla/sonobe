use crate::{frontend::FCircuit, Error};
use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar};
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use std::marker::PhantomData;

use super::zcash_hash_gadget::ZcashHashGadget;

#[derive(Clone, Debug)]
pub struct TCircuit<F: PrimeField>
where
    F: Absorb,
{
    _f: PhantomData<F>,
    poseidon_config: PoseidonConfig<F>,
}
impl<F: PrimeField> FCircuit<F> for TCircuit<F>
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
        1
    }

    fn external_inputs_len(&self) -> usize {
        // The raw T vector which should be secret
        // The size of T should match whatever number is here
        3
    }
    fn step_native(
        &self,
        i: usize,
        z_i: Vec<F>,
        external_inputs: Vec<F>, // inputs that are not part of the state
    ) -> Result<Vec<F>, Error> {
        let h = ZcashHashGadget::hash_scalar_fields(
            self.poseidon_config.clone(),
            external_inputs,
            z_i[0],
        );
        Ok(vec![h])
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
        let h: FpVar<F> = CRHGadget::<F>::evaluate(&crh_params, &external_inputs)?;
        //? Can't assert here?
        // assert_eq!(z_i[0], h);
        Ok(vec![h])
    }
}
