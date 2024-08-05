use crate::frontend::FCircuit;
use crate::Error;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar, ToBytesGadget};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug)]
pub struct MerkleTreeCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for MerkleTreeCircuit<F> {
    type Params = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        4 // TODO: The final root hash will be of length 1
    }

    fn external_inputs_len(&self) -> usize {
        0 // TODO: We will take 4 inputs to create the Merkle tree
    }

    fn step_native(
        &self,
        _i: usize,
        z_i: Vec<F>,
        _external_inputs: Vec<F>,
    ) -> Result<Vec<F>, Error> {
        // Use rs-merkle to create a Merkle tree and get the root hash
        let leaf_hashes: Vec<[u8; 32]> = z_i
            .iter()
            .map(|leaf| {
                let bytes = leaf.into_bigint().to_bytes_le();
                let mut hash_input = [0u8; 32];
                hash_input[..bytes.len()].copy_from_slice(&bytes);
                Sha256::hash(&hash_input)
            })
            .collect();

        let tree = MerkleTree::<Sha256>::from_leaves(&leaf_hashes);
        // Convert the root hash to the PrimeField element
        let root_hash = F::from_be_bytes_mod_order(&tree.root().unwrap());

        Ok(vec![root_hash, root_hash, root_hash, root_hash])
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Use a dummy constraint system to hash the leaf values
        let mut leaf_hashes: Vec<[u8; 32]> = vec![];

        for leaf in z_i.iter() {
            let bytes = leaf.to_bytes()?;
            let bytes_converted: Vec<u8> = bytes.iter().map(|byte| byte.value().unwrap()).collect();
            let mut hash_input = [0u8; 32];
            hash_input[..bytes_converted.len()].copy_from_slice(&bytes_converted);
            let hash = Sha256::hash(&hash_input);
            leaf_hashes.push(hash);
        }

        // Create the Merkle tree from leaf hashes
        let tree = MerkleTree::<Sha256>::from_leaves(&leaf_hashes);

        // Get the root hash of the Merkle tree
        let root_hash = tree.root().ok_or(SynthesisError::AssignmentMissing)?;

        // Convert the root hash to a field element
        let root_hash_field = F::from_be_bytes_mod_order(&root_hash);

        // Convert the root hash field element to an FpVar
        let root_hash = FpVar::new_witness(cs, || Ok(root_hash_field))?;
        Ok(vec![
            root_hash.clone(),
            root_hash.clone(),
            root_hash.clone(),
            root_hash.clone(),
        ])
    }
}
