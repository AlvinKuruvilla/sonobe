use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::ConstraintSystem;
use folding_schemes::zcash::merkle_gadget::MerkleTreeGadget;
fn main() {
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Create leaves
    let leaf_values: Vec<Fr> = vec![10, 20, 30, 40].into_iter().map(Fr::from).collect();

    // Convert leaves to FpVar
    let leaves_fpvar: Vec<_> = leaf_values
        .iter()
        .map(|&leaf| FpVar::new_input(cs.clone(), || Ok(leaf)).unwrap())
        .collect();

    // Create root hash
    let root_hash = MerkleTreeGadget::create_merkle_tree(leaves_fpvar.clone()).unwrap();
    let root_hash_fpvar = FpVar::new_input(cs.clone(), || Ok(root_hash.value().unwrap())).unwrap();

    // Choose a leaf index to prove and verify (e.g., index 0)
    let leaf_index = 0;
    let leaf_hash_fpvar = leaves_fpvar[leaf_index].clone();

    // Generate proof for the chosen leaf
    let proof_fpvar = MerkleTreeGadget::generate_proof(leaf_index, &leaves_fpvar).unwrap();

    // Verify the chosen leaf
    let is_valid =
        MerkleTreeGadget::verify_proof(leaf_hash_fpvar, proof_fpvar, root_hash_fpvar).unwrap();

    println!("Leaf node is valid: {}", is_valid.value().unwrap());
}
