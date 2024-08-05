use ark_crypto_primitives::crh::{
    sha256::{
        constraints::{Sha256Gadget, UnitVar},
        Sha256,
    },
    CRHScheme, CRHSchemeGadget,
};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::{
    eq::EqGadget, fields::fp::FpVar, prelude::Boolean, ToBytesGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::SynthesisError;

pub struct MerkleTreeGadget;
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
    pub fn verify_leaf_node<F: PrimeField>(
        leaf_hash: FpVar<F>,
        proof: Vec<FpVar<F>>,
        root_hash: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // Initialize current hash with the leaf hash
        let mut current_hash = leaf_hash;

        // Iterate through proof hashes to compute the hash up to the root
        for sibling_hash in proof {
            // Combine the current hash with the sibling hash
            let pair = vec![current_hash.clone(), sibling_hash.clone()];

            // Compute the hash of the pair
            let hash_result = hash_pair(pair[0].clone(), pair[1].clone())?;

            // Update current hash with the computed pair hash
            current_hash = hash_result[0].clone();
        }

        // Check if the computed hash matches the root hash
        current_hash.is_eq(&root_hash)
    }
    pub fn create_merkle_tree<F: PrimeField>(
        leaves: Vec<FpVar<F>>,
    ) -> Result<FpVar<F>, SynthesisError> {
        MerkleTreeGadget::create_root_hash(leaves)
    }
    pub fn generate_proof<F: PrimeField>(
        index: usize,
        leaves: &[FpVar<F>],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let leaves = leaves.to_owned();
        if leaves.len() % 2 != 0 {
            panic!("Number of leaves must be even");
        }

        let mut current_level = leaves.clone();
        let mut proof = vec![];
        let mut idx = index;

        while current_level.len() > 1 {
            let mut next_level = vec![];
            for i in (0..current_level.len()).step_by(2) {
                if i == idx || i + 1 == idx {
                    let sibling_idx = if i == idx { i + 1 } else { i };
                    proof.push(current_level[sibling_idx].clone());
                    idx = next_level.len();
                }
                let hash =
                    hash_pair(current_level[i].clone(), current_level[i + 1].clone())?[0].clone();
                next_level.push(hash);
            }

            current_level = next_level;
        }

        Ok(proof)
    }
    pub fn verify_proof<F: PrimeField>(
        leaf: FpVar<F>,
        proof: Vec<FpVar<F>>,
        root: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        MerkleTreeGadget::verify_leaf_node(leaf, proof, root)
    }
}
