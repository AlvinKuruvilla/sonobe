use ark_bn254::Fr;
use ark_crypto_primitives::{
    crh::{poseidon::CRH, CRHScheme},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;

use crate::{transcript::poseidon::poseidon_canonical_config, Error};

use super::spend_key::SpendKey;

pub struct PublicLedgerGadget<F: PrimeField + Absorb> {
    poseidon_config: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> PublicLedgerGadget<F> {
    pub fn validate_scalar_transaction_hash(
        &self,
        transaction_hash: F,
        transactions: Vec<F>,
    ) -> Result<F, Error> {
        let mut inputs: Vec<F> = Vec::new();

        // Add all transaction field elements to inputs
        for transaction in transactions {
            inputs.push(transaction);
        }

        // Compute the hash using Poseidon
        let h = CRH::<F>::evaluate(&self.poseidon_config, inputs).unwrap();
        assert_eq!(transaction_hash, h);
        Ok(h)
    }
    pub fn validate_scalar_spend_key_hash(
        spend_key_hash: Fr,
        spend_keys: Vec<SpendKey>,
    ) -> Result<Fr, Error> {
        let mapped_spend_keys: Vec<Fr> = spend_keys.iter().map(|sk| sk.to_fr()).collect();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        let spend_key_secret_hash =
            CRH::<Fr>::evaluate(&poseidon_config.clone(), mapped_spend_keys.clone()).unwrap();
        assert_eq!(spend_key_secret_hash, spend_key_hash);
        Ok(spend_key_secret_hash)
    }
}
