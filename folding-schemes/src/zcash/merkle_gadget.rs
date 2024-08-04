use ark_crypto_primitives::crh::{
    sha256::{
        constraints::{Sha256Gadget, UnitVar},
        Sha256,
    },
    CRHScheme, CRHSchemeGadget,
};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::{fields::fp::FpVar, ToBytesGadget, ToConstraintFieldGadget};
use ark_relations::r1cs::SynthesisError;

pub struct MerkleTreeGadget;
// TODO: See if we can leverage a library like merkle_rs instead of having to do this work ourselves. This will make leaf node
// verification most likely simpler
pub fn hash_pair<F: PrimeField>(
    left: FpVar<F>,
    right: FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let unit_var = UnitVar::default();
    let mut hash_input = vec![];
    hash_input.extend_from_slice(&left.to_bytes()?);
    hash_input.extend_from_slice(&right.to_bytes()?);
    let hash_bytes = Sha256Gadget::evaluate(&unit_var, &hash_input)?;
    hash_bytes.0.to_constraint_field()
}
pub fn hash_scalar_field_pair<F: PrimeField>(left: F, right: F) -> F {
    let mut hash_input = left.into_bigint().to_bytes_le();
    hash_input.extend(&right.into_bigint().to_bytes_le());
    let hash_bytes = Sha256::evaluate(&(), hash_input).unwrap();
    hash_bytes.to_field_elements().unwrap()[0]
}
impl MerkleTreeGadget {
    pub fn create_root_hash<F: PrimeField>(
        leaves: Vec<FpVar<F>>,
    ) -> Result<FpVar<F>, SynthesisError> {
        if leaves.len() % 2 != 0 {
            panic!("Number of leaves must be even");
        }
        let mut current_level = leaves;

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let hash =
                    hash_pair(current_level[i].clone(), current_level[i + 1].clone())?[0].clone();
                next_level.push(hash);
            }

            current_level = next_level;
        }

        Ok(current_level[0].clone())
    }
    pub fn create_root_hash_from_scalar_fields<F: PrimeField>(leaves: Vec<F>) -> F {
        if leaves.len() % 2 != 0 {
            panic!("Number of leaves must be even");
        }
        let mut current_level = leaves;

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let hash = hash_scalar_field_pair(current_level[i], current_level[i + 1]);
                next_level.push(hash);
            }

            current_level = next_level;
        }

        current_level[0]
    }
}
