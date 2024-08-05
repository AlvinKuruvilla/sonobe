use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::ConstraintSystem;
use folding_schemes::zcash::merkle_gadget::{hash_pair, MerkleTreeGadget};
pub fn main() {
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Create leaves
    let leaf_values: Vec<Fr> = vec![10, 20, 30, 40].into_iter().map(Fr::from).collect();

    // Convert leaves to FpVar
    let leaves_fpvar: Vec<_> = leaf_values
        .iter()
        .map(|&leaf| FpVar::new_input(cs.clone(), || Ok(leaf)).unwrap())
        .collect();

    // Create root hash
    let root_hash = MerkleTreeGadget::create_root_hash(leaves_fpvar.clone()).unwrap();
    let root_hash_fpvar = FpVar::new_input(cs.clone(), || Ok(root_hash.value().unwrap())).unwrap();

    // Generate proof for leaf1 (proof path: leaf2, hash(leaf3, leaf4))
    let hash_leaf3_leaf4 =
        hash_pair(leaves_fpvar[2].clone(), leaves_fpvar[3].clone()).unwrap()[0].clone();
    let proof_fpvar = vec![
        FpVar::new_input(cs.clone(), || Ok(leaf_values[1])).unwrap(),
        FpVar::new_input(cs.clone(), || Ok(hash_leaf3_leaf4.value().unwrap())).unwrap(),
    ];

    // Verify leaf1
    let is_valid =
        MerkleTreeGadget::verify_leaf_node(leaves_fpvar[0].clone(), proof_fpvar, root_hash_fpvar)
            .unwrap();

    println!("Leaf node is valid: {}", is_valid.value().unwrap());
}
