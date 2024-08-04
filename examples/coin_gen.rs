/// We will keep the spend key map to act like a "global" prover
/// The map will be filled by am (u32, sn) pair
/// We will also keep extra data (in probably key) on whether or not that transaction has been spent
/// to emulate double spend protection
///
/// The setup for this tester can simply be to init a vector of 10 elements where each pair is a random sn, trapdoor pair
/// Unlike he normal split transaction model: if Alice requests 5 and you give 10 you get 5 back
/// When we spend 4 "coins" we will marking 4 entries in the map because all entries are assumed to be 1 unit of value
use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as G1};
use ark_grumpkin::{constraints::GVar as GVar2, Projective as G2};
use ark_std::UniformRand;
use folding_schemes::commitment::kzg::KZG;
use folding_schemes::folding::nova::{Nova, PreprocessorParam};
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::zcash::coin_circuit::CoinCircuit;
use folding_schemes::zcash::spend_key::{SpendKey, SpendKeyMap};
use folding_schemes::FoldingScheme;
use folding_schemes::{commitment::pedersen::Pedersen, frontend::FCircuit};
use std::time::Instant;
pub fn prepare_input(length: i32) -> Vec<(Fr, Fr, Fr, i32)> {
    let mut rng = ark_std::test_rng();
    // let mut value_rng = rand::thread_rng();

    let v: Vec<(Fr, Fr, Fr, i32)> = (0..length)
        .map(|_| {
            (
                Fr::rand(&mut rng),
                Fr::rand(&mut rng),
                Fr::rand(&mut rng),
                // This is just to test the splitting functionality
                30,
            )
        })
        .collect();
    v
}
pub fn main() {
    std::env::set_var("RUST_BACKTRACE", "full");
    let n_steps: i32 = 10;
    let data = prepare_input(n_steps);
    let mut spend_map = SpendKeyMap::new(data.clone());
    for i in 0..n_steps {
        // Set the initial state with two elements
        let z_0 = vec![
            data[i as usize].0,
            data[i as usize].1,
            data[i as usize].2, // for coin value
            data[i as usize].1, // for address gen
        ];
        let f_circuit = CoinCircuit::<Fr>::new(()).unwrap(); // Ensure to use Fq here
        let poseidon_config = poseidon_canonical_config::<Fr>();
        let mut rng = rand::rngs::OsRng;
        let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit);
        pub type NOVA =
            Nova<G1, GVar, G2, GVar2, CoinCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>>;
        let nova_params = NOVA::preprocess(&mut rng, &nova_preprocess_params).unwrap();
        // Initialize the folding scheme engine, in our case we use Nova
        let mut nova = NOVA::init(&nova_params, f_circuit, z_0.clone()).unwrap();
        // Run n steps of the folding iteration
        for i in 0..n_steps {
            let start = Instant::now();
            nova.prove_step(rng, vec![], None).unwrap();
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
    // Spend 4 coins
    spend_map.spend_coins(vec![0, 1, 2, 3]);
    assert!(spend_map.inner().get(&0).unwrap().is_spent());
    assert!(spend_map.inner().get(&1).unwrap().is_spent());
    assert!(spend_map.inner().get(&2).unwrap().is_spent());
    assert!(spend_map.inner().get(&3).unwrap().is_spent());
    let old_len = spend_map.inner().keys().len();
    let mut rng = ark_std::test_rng();
    let key1 = SpendKey::new(Fr::rand(&mut rng), false, 15);
    let key2 = SpendKey::new(Fr::rand(&mut rng), false, 15);
    spend_map.split_coin(0, key1, key2);
    assert_eq!(old_len + 1, spend_map.inner().keys().len());
    let t = spend_map
        .inner()
        .get(&spend_map.find_biggest_id())
        .unwrap()
        .to_owned()
        .value();
    assert_eq!(t, 15)
}
