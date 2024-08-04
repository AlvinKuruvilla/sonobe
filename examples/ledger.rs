use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as G1};
use ark_crypto_primitives::crh::{poseidon::CRH, CRHScheme};
use ark_grumpkin::constraints::GVar as GVar2;
use ark_grumpkin::Projective as G2;
use ark_std::UniformRand;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    zcash::{public_ledger::PublicLedgerCircuit, spend_key::SpendKey, t_circuit::TCircuit},
    FoldingScheme,
};
use std::time::Instant;

pub fn prepare_data(length: i32) -> Vec<(SpendKey, Fr)> {
    let mut rng = ark_std::test_rng();
    let v: Vec<(SpendKey, Fr)> = (0..length)
        .map(|_| (SpendKey::from_random(), Fr::rand(&mut rng)))
        .collect();
    v
}
pub fn test() {
    let n_steps: i32 = 1;
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let data = prepare_data(2);
    let (spend_keys, transaction_hashes): (Vec<_>, Vec<_>) = data.into_iter().unzip();
    let mapped_spend_keys: Vec<Fr> = spend_keys.iter().map(|sk| sk.to_fr()).collect();
    println!("Spend Key Length: {:?}", mapped_spend_keys.len());
    let spend_key_secret_hash =
        CRH::<Fr>::evaluate(&poseidon_config, mapped_spend_keys.clone()).unwrap();
    let transaction_hashes_secret_hash =
        CRH::<Fr>::evaluate(&poseidon_config, transaction_hashes.clone()).unwrap();
    let z_0 = vec![transaction_hashes_secret_hash];
    let f_circuit = PublicLedgerCircuit::<Fr>::new(poseidon_config.clone()).unwrap();
    let mut rng = rand::rngs::OsRng;
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    pub type NOVA =
        Nova<G1, GVar, G2, GVar2, PublicLedgerCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>>;
    let nova_params = NOVA::preprocess(&mut rng, &nova_preprocess_params).unwrap();
    // Initialize the folding scheme engine, in our case we use Nova
    let mut nova = NOVA::init(&nova_params, f_circuit, z_0.clone()).unwrap();
    for i in 0..n_steps {
        let start = Instant::now();
        // nova.prove_step(rng, mapped_spend_keys.clone(), None)
        //     .unwrap();
        nova.prove_step(rng, transaction_hashes.clone(), None)
            .unwrap();
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
pub fn main() {
    let mut rng = ark_std::test_rng();
    let n_steps: i32 = 1;
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let transaction_hashes: Vec<Fr> =
        vec![Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng)];
    let spend_keys: Vec<SpendKey> = vec![
        SpendKey::from_random(),
        SpendKey::from_random(),
        SpendKey::from_random(),
    ];
    let mapped_spend_keys: Vec<Fr> = spend_keys.iter().map(|sk| sk.to_fr()).collect();
    let spend_key_secret_hash =
        CRH::<Fr>::evaluate(&poseidon_config.clone(), mapped_spend_keys.clone()).unwrap();

    let secret_hash =
        CRH::<Fr>::evaluate(&poseidon_config.clone(), transaction_hashes.clone()).unwrap();
    let z_0 = vec![secret_hash];
    let f_circuit = TCircuit::<Fr>::new(poseidon_config.clone()).unwrap();
    let mut rng = rand::rngs::OsRng;
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
    pub type NOVA = Nova<G1, GVar, G2, GVar2, TCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>>;
    let nova_params = NOVA::preprocess(&mut rng, &nova_preprocess_params).unwrap();
    // Initialize the folding scheme engine, in our case we use Nova
    let mut nova = NOVA::init(&nova_params, f_circuit, z_0.clone()).unwrap();
    for i in 0..n_steps {
        let start = Instant::now();
        nova.prove_step(rng, transaction_hashes.clone(), None)
            .unwrap();
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

    let z_0 = vec![spend_key_secret_hash];

    let f_circuit = TCircuit::<Fr>::new(poseidon_config.clone()).unwrap();
    let mut rng = rand::rngs::OsRng;
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let nova_params = NOVA::preprocess(&mut rng, &nova_preprocess_params).unwrap();
    // Initialize the folding scheme engine, in our case we use Nova
    let mut nova = NOVA::init(&nova_params, f_circuit, z_0.clone()).unwrap();
    for i in 0..n_steps {
        let start = Instant::now();
        nova.prove_step(rng, transaction_hashes.clone(), None)
            .unwrap();
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
