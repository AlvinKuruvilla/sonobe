use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar, ToBytesGadget};
use ark_relations::r1cs::ConstraintSystem;

pub fn fpvar_to_bytes<F: PrimeField>(value: FpVar<F>) -> Vec<u8> {
    // Convert FpVar to bytes
    let bytes = value.to_bytes().unwrap();

    // Convert bytes to Vec<u8>
    return bytes.iter().map(|byte| byte.value().unwrap()).collect();
}
pub fn bytes_to_field_element_and_field_element_variable(bytes: Vec<u8>) -> (Fr, FpVar<Fr>) {
    let cs = ConstraintSystem::new_ref();
    // Create a constraint system
    let a = Fr::from_le_bytes_mod_order(&bytes);
    let recon = FpVar::new_witness(cs, || Ok(a)).unwrap();
    (a, recon)
}
