use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;
use ark_std::UniformRand;
use folding_schemes::zcash::transaction::{Address, Blockchain, Transaction};
use rand::Rng;
use std::time::Instant;

// Helper function to generate a random value in the specified range
fn generate_random_in_range() -> Fr {
    let mut rng = rand::thread_rng();
    Fr::from(rng.gen_range(0..200))
}

pub fn main() {
    let mut blockchain = Blockchain::default();
    let mut rng = ark_std::test_rng();

    for i in 1..100 {
        let start = Instant::now();
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate random transaction data
        let tid = FpVar::new_input(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();
        let value = FpVar::new_input(cs.clone(), || Ok(generate_random_in_range())).unwrap();
        let sender_secret = FpVar::new_input(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();
        let receiver_secret_1 = FpVar::new_input(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();
        let receiver_secret_2 = FpVar::new_input(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();
        let sn_secret = FpVar::new_input(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();

        // Create the original transaction
        let t = Transaction::new(
            tid,
            value.clone(),
            sender_secret.clone(),
            receiver_secret_1.clone(),
            sn_secret.clone(), // Clone the serial number secret for later use
        );

        // Define the split values and new receiver addresses
        let split_values = vec![
            FpVar::new_input(cs.clone(), || Ok(generate_random_in_range())).unwrap(),
            FpVar::new_input(cs.clone(), || Ok(generate_random_in_range())).unwrap(),
        ];
        let new_receiver_addresses = vec![
            Address::new(receiver_secret_1.clone()),
            Address::new(receiver_secret_2.clone()),
        ];

        // Perform the transaction split
        let split_transactions =
            t.split_transaction(split_values, new_receiver_addresses, sender_secret);

        // Append each split transaction to the blockchain
        for split_tx in split_transactions {
            blockchain.append_transaction(split_tx.root(), split_tx.serial_number());
        }

        println!("Nova::prove_step {}: {:?}", i, start.elapsed());
    }

    // After the loop, introduce a duplicate serial number deliberately
    let cs = ConstraintSystem::<Fr>::new_ref();
    let tid = FpVar::new_input(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();
    let value = FpVar::new_input(cs.clone(), || Ok(generate_random_in_range())).unwrap();
    let sender_secret = FpVar::new_input(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();
    let receiver_secret = FpVar::new_input(cs.clone(), || Ok(Fr::rand(&mut rng))).unwrap();
    let sn_secret = FpVar::new_input(cs.clone(), || Ok(Fr::from(110))).unwrap();

    let extra_tx = Transaction::new(
        tid.clone(),
        value.clone(),
        sender_secret.clone(),
        receiver_secret.clone(),
        sn_secret.clone(),
    );

    // This line should cause a panic due to duplicate serial numbers
    blockchain.append_transaction(extra_tx.root(), extra_tx.serial_number());

    let dupe_tx = Transaction::new(
        tid,
        value,
        sender_secret.clone(),
        receiver_secret.clone(),
        sn_secret.clone(), // Deliberately reuse the same serial number secret to trigger the expected panic
    );
    blockchain.append_transaction(dupe_tx.root(), dupe_tx.serial_number());
    println!(
        "This line should not be reached if the duplicate serial number check works correctly."
    );
}
