use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;
use folding_schemes::zcash::byte_utils::{
    bytes_to_field_element_and_field_element_variable, fpvar_to_bytes,
};
pub fn main() {
    let cs = ConstraintSystem::new_ref();

    let mut rng = rand::thread_rng();
    let field_element = Fr::rand(&mut rng);

    // Create FpVar from field element
    let leaf =
        FpVar::<Fr>::new_variable(cs.clone(), || Ok(field_element), AllocationMode::Input).unwrap();
    let bytes_converted = fpvar_to_bytes(leaf.clone());
    let (a, recon) = bytes_to_field_element_and_field_element_variable(bytes_converted);
    let res = recon.is_eq(&leaf).unwrap().value().unwrap();
    let res2 = a == field_element;

    println!("{res}");
    println!("{res2}");
}
