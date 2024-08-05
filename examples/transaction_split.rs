use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;
use folding_schemes::zcash::merkle_gadget::MerkleTreeGadget;
fn main() {
    // TODO: Test with splitting logic
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Create leaves
    let leaf_values: Vec<Fr> = vec![10, 20, 30, 40].into_iter().map(Fr::from).collect();

    // Convert leaves to FpVar
    let leaves_fpvar: Vec<_> = leaf_values
        .iter()
        .map(|&leaf| FpVar::new_input(cs.clone(), || Ok(leaf)).unwrap())
        .collect();
    // Verify the chosen leaf
    let is_valid = MerkleTreeGadget::generate_proof_and_validate(&leaves_fpvar, cs, vec![1]);

    println!("Leaf node is valid: {}", is_valid);
}
