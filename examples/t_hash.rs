use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as G1};
use ark_crypto_primitives::crh::poseidon::CRH;
use ark_crypto_primitives::crh::CRHScheme;
use ark_grumpkin::constraints::GVar as GVar2;
use ark_grumpkin::Projective as G2;
use folding_schemes::FoldingScheme;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    zcash::t_circuit::TCircuit,
};
use std::str::FromStr;
use std::time::Instant;
pub fn main() {
    let n_steps: i32 = 1;
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let T: Vec<Fr> = vec!["1", "2", "3"]
        .into_iter()
        .map(|x| Fr::from_str(x).unwrap())
        .collect();
    let secret_hash = CRH::<Fr>::evaluate(&poseidon_config, T.clone()).unwrap();

    let z_0 = vec![secret_hash];
    let f_circuit = TCircuit::<Fr>::new(poseidon_config.clone()).unwrap();
    let mut rng = rand::rngs::OsRng;
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    pub type NOVA = Nova<G1, GVar, G2, GVar2, TCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>>;
    let nova_params = NOVA::preprocess(&mut rng, &nova_preprocess_params).unwrap();
    // Initialize the folding scheme engine, in our case we use Nova
    let mut nova = NOVA::init(&nova_params, f_circuit, z_0.clone()).unwrap();
    for i in 0..n_steps {
        let start = Instant::now();
        nova.prove_step(rng, T.clone(), None).unwrap();
        println!("Nova::prove_step {}: {:?}", i, start.elapsed());
    }
    let (running_instance, incoming_instance, cyclefold_instance) = nova.instances();

    println!("Run the Nova's IVC verifier");
    NOVA::verify(
        nova_params.1,
        z_0,
        nova.state(), // latest state
        Fr::from(n_steps as u32),
        running_instance,
        incoming_instance,
        cyclefold_instance,
    )
    .unwrap();
}
