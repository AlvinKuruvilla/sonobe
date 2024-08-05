/// This is a circuit to approximate the coin creation process
/// Like the zcash paper
/// The components are the commitment, the random serial number and the trapdoor
use std::marker::PhantomData;

use crate::{frontend::FCircuit, Error};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::coin_gadget::ZcashCoinGadget;

#[derive(Clone, Copy, Debug)]
pub struct CoinCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}
impl<F: PrimeField> FCircuit<F> for CoinCircuit<F> {
    type Params = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        // This should be 3 because we will provide as input sn and r, and cm is hash(sn)
        4
    }

    fn external_inputs_len(&self) -> usize {
        0
    }
    // NOTE: Since the types do not play well with the FCircuit trait we approximate the Pedersen commitment using sha256
    fn step_native(
        &self,
        _i: usize,
        z_i: Vec<F>,
        _external_inputs: Vec<F>,
    ) -> Result<Vec<F>, Error> {
        let sn = z_i[0];
        let r = z_i[1];
        let address_sk = z_i[2]; // address seed
        let data = ZcashCoinGadget::generate_coin_from_scalar_fields(sn, r, address_sk);
        let cm_root_hash = data[0];
        let address_pk = data[3];
        Ok(vec![cm_root_hash, sn, r, address_pk])
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let sn = &z_i[0];
        let r = &z_i[1];
        let data = ZcashCoinGadget::generate_coin(sn.clone(), r.clone(), z_i[2].clone(), cs)?;
        let cm = data[0].clone();
        Ok(vec![cm, sn.clone(), r.clone(), data[3].clone()])
    }
}
