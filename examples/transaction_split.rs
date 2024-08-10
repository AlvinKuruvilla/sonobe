use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;
use folding_schemes::zcash::merkle_gadget::MerkleTreeGadget;
fn main() {
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Create leaves
    // NOTE: the original vector was [10, 20, 15, 15, 40], the "30" element was manually split to test if we can
    // validate all elements in a set of leaves
    // We may need to further test this ability but will need to consult notes for that
    let leaf_values: Vec<Fr> = vec![10, 20, 15, 15, 40].into_iter().map(Fr::from).collect();
    let leaf_values2: Vec<Fr> = vec![50, 60, 70, 80, 90].into_iter().map(Fr::from).collect();

    // Convert leaves to FpVar
    let leaves_fpvar: Vec<_> = leaf_values
        .iter()
        .map(|&leaf| FpVar::new_input(cs.clone(), || Ok(leaf)).unwrap())
        .collect();
    let leaves_fpvar2: Vec<_> = leaf_values2
        .iter()
        .map(|&leaf| FpVar::new_input(cs.clone(), || Ok(leaf)).unwrap())
        .collect();

    // Create an inner Merkle tree with the first set of leaves
    let inner_leaves_fpvar: Vec<_> = leaves_fpvar.to_vec();
    // Create another inner Merkle tree with the second set of leaves
    let inner_leaves_fpvar2: Vec<_> = leaves_fpvar2.to_vec(); // Adjust as needed

    // Generate the root of the inner Merkle trees
    let inner_root = MerkleTreeGadget::create_root_hash(inner_leaves_fpvar, cs.clone());
    let inner_root2 = MerkleTreeGadget::create_root_hash(inner_leaves_fpvar2, cs.clone());

    // Create a new vector of leaves for the outer tree
    let new_outer_leaf_values: Vec<_> = vec![100, 200, 300].into_iter().map(Fr::from).collect();

    // Convert the new leaves to FpVar and the two inner roots
    let mut outer_leaves_fpvar: Vec<_> = new_outer_leaf_values
        .iter()
        .map(|&leaf| FpVar::new_input(cs.clone(), || Ok(leaf)).unwrap())
        .collect();
    outer_leaves_fpvar.push(inner_root);
    outer_leaves_fpvar.push(inner_root2);

    // Verify each leaf of the outer tree
    for (idx, _) in outer_leaves_fpvar.iter().enumerate() {
        // Verify the chosen leaf
        let is_valid = MerkleTreeGadget::generate_proof_and_validate(
            &outer_leaves_fpvar,
            cs.clone(),
            vec![idx],
        );

        println!("Leaf node {} is valid: {}", idx, is_valid);
    }
}
