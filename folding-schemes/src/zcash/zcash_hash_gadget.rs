use ark_crypto_primitives::{
    crh::{poseidon::CRH, CRHScheme},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;

pub struct ZcashHashGadget;
impl ZcashHashGadget {
    pub fn hash_scalar_fields<F: PrimeField + Absorb>(
        poseidon_config: PoseidonConfig<F>,
        field_elements: Vec<F>,
        public_hash: F,
    ) -> F {
        let h = CRH::<F>::evaluate(&poseidon_config, field_elements).unwrap();
        assert_eq!(public_hash, h);
        h
    }
}
