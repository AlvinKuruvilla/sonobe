use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

pub struct Sender<F: PrimeField> {
    address: String,
    key: FpVar<F>,
}
pub struct Reciever<F: PrimeField> {
    address: String,
    key: FpVar<F>,
}
