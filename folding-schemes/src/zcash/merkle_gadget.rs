use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar, ToBytesGadget};
use ark_relations::r1cs::ConstraintSystemRef;
use rs_merkle::MerkleProof;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};
pub struct MerkleTreeGadget;

impl MerkleTreeGadget {
    pub fn create_root_hash_from_scalar_fields<F: PrimeField>(leaves: Vec<F>) -> F {
        // Use rs-merkle to create a Merkle tree and get the root hash
        let leaf_hashes: Vec<[u8; 32]> = leaves
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
        F::from_be_bytes_mod_order(&tree.root().unwrap())
    }
    pub fn create_root_hash<F: PrimeField>(
        leaves: Vec<FpVar<F>>,
        cs: ConstraintSystemRef<F>,
    ) -> FpVar<F> {
        // Use a dummy constraint system to hash the leaf values
        let mut leaf_hashes: Vec<[u8; 32]> = vec![];

        for leaf in leaves.iter() {
            let bytes = leaf.to_bytes().unwrap();
            let bytes_converted: Vec<u8> = bytes.iter().map(|byte| byte.value().unwrap()).collect();
            let mut hash_input = [0u8; 32];
            hash_input[..bytes_converted.len()].copy_from_slice(&bytes_converted);
            let hash = Sha256::hash(&hash_input);
            leaf_hashes.push(hash);
        }

        // Create the Merkle tree from leaf hashes
        let tree = MerkleTree::<Sha256>::from_leaves(&leaf_hashes);

        // Get the root hash of the Merkle tree
        let root_hash = tree.root().unwrap();

        // Convert the root hash to a field element
        let root_hash_field = F::from_le_bytes_mod_order(&root_hash);

        // Convert the root hash field element to an FpVar
        FpVar::new_witness(cs, || Ok(root_hash_field)).unwrap()
    }
    pub fn create_merkle_tree<F: PrimeField>(
        leaves: Vec<FpVar<F>>,
        cs: ConstraintSystemRef<F>,
    ) -> MerkleTree<Sha256> {
        let mut leaf_hashes: Vec<[u8; 32]> = vec![];

        for leaf in leaves.iter() {
            let bytes = leaf.to_bytes().unwrap();
            let bytes_converted: Vec<u8> = bytes.iter().map(|byte| byte.value().unwrap()).collect();
            let mut hash_input = [0u8; 32];
            hash_input[..bytes_converted.len()].copy_from_slice(&bytes_converted);
            let hash = Sha256::hash(&hash_input);
            leaf_hashes.push(hash);
        }

        // Create the Merkle tree from leaf hashes
        MerkleTree::<Sha256>::from_leaves(&leaf_hashes)
    }

    pub fn generate_proof_and_validate<F: PrimeField>(
        leaves: &[FpVar<F>],
        cs: ConstraintSystemRef<F>,
        indices_to_prove: Vec<usize>,
    ) -> bool {
        let tree = Self::create_merkle_tree(leaves.to_vec(), cs);
        let mut leaf_hashes: Vec<[u8; 32]> = vec![];

        for leaf in leaves.iter() {
            let bytes = leaf.to_bytes().unwrap();
            let bytes_converted: Vec<u8> = bytes.iter().map(|byte| byte.value().unwrap()).collect();
            let mut hash_input = [0u8; 32];
            hash_input[..bytes_converted.len()].copy_from_slice(&bytes_converted);
            let hash = Sha256::hash(&hash_input);
            leaf_hashes.push(hash);
        }

        let leaves_to_prove: Vec<_> = indices_to_prove
            .iter()
            .filter_map(|&i| leaf_hashes.get(i))
            .cloned() // Clone the values if necessary
            .collect();

        let merkle_proof = tree.proof(&indices_to_prove);
        let merkle_root = tree.root().unwrap();
        // println!("Merkle root: {:?}", merkle_root);
        // Serialize proof to pass it to the client
        let proof_bytes = merkle_proof.to_bytes();

        // Parse proof back on the client
        let proof = MerkleProof::<Sha256>::try_from(proof_bytes).unwrap();
        let ret = proof.verify(
            merkle_root,
            &indices_to_prove,
            &leaves_to_prove,
            leaves.len(),
        );
        assert!(ret);
        ret
    }
}
