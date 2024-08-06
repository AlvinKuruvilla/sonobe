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

    // Convert leaves to FpVar
    let leaves_fpvar: Vec<_> = leaf_values
        .iter()
        .map(|&leaf| FpVar::new_input(cs.clone(), || Ok(leaf)).unwrap())
        .collect();
    for (idx, _) in leaves_fpvar.iter().enumerate() {
        // Verify the chosen leaf
        let is_valid =
            MerkleTreeGadget::generate_proof_and_validate(&leaves_fpvar, cs.clone(), vec![idx]);

        println!("Leaf node is valid: {}", is_valid);
    }
}
