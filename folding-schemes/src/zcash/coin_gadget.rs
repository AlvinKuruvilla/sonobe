use ark_crypto_primitives::crh::{
    sha256::{
        constraints::{Sha256Gadget, UnitVar},
        Sha256,
    },
    CRHScheme, CRHSchemeGadget,
};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::{fields::fp::FpVar, ToBytesGadget, ToConstraintFieldGadget};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::merkle_gadget::MerkleTreeGadget;

pub struct ZcashCoinGadget;
impl ZcashCoinGadget {
    // NOTE: It is the caller's responsibility to ensure that the address_seed is random
    pub fn generate_coin_from_scalar_fields<F: PrimeField>(
        serial_number: F,
        r: F,
        address_seed: F,
    ) -> Vec<F> {
        let leaves = vec![serial_number, serial_number];
        let cm_root_hash = MerkleTreeGadget::create_root_hash_from_scalar_fields(leaves);
        let address_pk: F = Sha256::evaluate(&(), address_seed.into_bigint().to_bytes_le())
            .unwrap()
            .to_field_elements()
            .unwrap()[0];
        vec![cm_root_hash, serial_number, r, address_pk]
    }
    // NOTE: It is the caller's responsibility to ensure that the address_seed is random
    pub fn generate_coin<F: PrimeField>(
        serial_number: FpVar<F>,
        r: FpVar<F>,
        address_seed: FpVar<F>,
        cs: ConstraintSystemRef<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let leaves = vec![serial_number.clone(), serial_number.clone()];
        let cm_root_hash = MerkleTreeGadget::create_root_hash(leaves, cs);
        let mut holder = vec![];
        holder.extend_from_slice(&address_seed.to_bytes().unwrap());
        let unit_var = UnitVar::default();
        let address_pk = &Sha256Gadget::evaluate(&unit_var, &holder)?
            .0
            .to_constraint_field()?[0];
        Ok(vec![cm_root_hash, serial_number, r, address_pk.clone()])
    }
}
