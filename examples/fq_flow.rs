use folding_schemes::commitment::kzg::KZG;
use folding_schemes::folding::nova::PreprocessorParam;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::zcash::fq_hasher::HashTwoFqCircuit;

use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as G1};
use ark_grumpkin::{constraints::GVar as GVar2, Projective as G2};
use folding_schemes::folding::nova::Nova;
use folding_schemes::FoldingScheme;
use folding_schemes::{commitment::pedersen::Pedersen, frontend::FCircuit};
use std::time::Instant;

pub fn main() {
    std::env::set_var("RUST_BACKTRACE", "full");
    let n_steps: i32 = 10;
    // Set the initial state with two elements
    let z_0 = vec![Fr::from(1_u32), Fr::from(2_u32)];
    // println!("z_0.len() = {:?}", z_0.len());
    // assert_eq!(z_0.len(), 5);
    let f_circuit = HashTwoFqCircuit::<Fr>::new(()).unwrap(); // Ensure to use Fq here
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    println!("Prepare Nova ProverParams & VerifierParams");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit);

    pub type N = Nova<G1, GVar, G2, GVar2, HashTwoFqCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>>;
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params).unwrap();

    // println!("z_0.len() = {:?}", z_0.len());
    // Initialize the folding scheme engine, in our case we use Nova
    let mut nova = N::init(&nova_params, f_circuit, z_0.clone()).unwrap();
    // Run n steps of the folding iteration
    for i in 0..n_steps {
        let start = Instant::now();
        nova.prove_step(rng, vec![], None).unwrap();
        println!("Nova::prove_step {}: {:?}", i, start.elapsed());
    }
    let (running_instance, incoming_instance, cyclefold_instance) = nova.instances();

    println!("Run the Nova's IVC verifier");
    let res = N::verify(
        nova_params.1,
        z_0,
        nova.state(), // latest state
        Fr::from(n_steps as u32),
        running_instance,
        incoming_instance,
        cyclefold_instance,
    );
    println!("{:?}", res);
}
