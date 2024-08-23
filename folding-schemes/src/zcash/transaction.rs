use std::{collections::HashMap, fmt::Display};

use ark_crypto_primitives::crh::{
    sha256::constraints::{Sha256Gadget, UnitVar},
    CRHSchemeGadget,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar, ToBytesGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::ConstraintSystem;
use ark_std::rand::thread_rng;

use super::merkle_gadget::MerkleTreeGadget;
type ROOT<F> = F;
type SN<F> = F;

#[derive(Clone)]
pub struct Address<F: PrimeField> {
    public_key: FpVar<F>,
    secret_key: FpVar<F>,
}
/// According to the Zcash paper, this is the address generation procedure. Hash the secret key to generate the pairs (pk, sk)
impl<F> Address<F>
where
    F: PrimeField,
{
    pub fn new(secret_key: FpVar<F>) -> Self {
        let mut holder = vec![];
        let unit_var: UnitVar<F> = UnitVar::default();
        holder.extend_from_slice(&secret_key.to_bytes().unwrap());

        let sn = Sha256Gadget::evaluate(&unit_var, &holder)
            .unwrap()
            .0
            .to_constraint_field()
            .unwrap()[0]
            .to_owned();
        Self {
            public_key: sn,
            secret_key,
        }
    }
    pub fn public_key(&self) -> FpVar<F> {
        self.public_key.clone()
    }
    pub fn secret_key(&self) -> FpVar<F> {
        self.secret_key.clone()
    }
}
/// A serial number for a transaction.
/// According to the zcash paper, the user u first samples ρ, which is a secret value that determines the coin’s serial number as
/// sn = hash(p)
/// For our purposes, 'value' encapsulates the result of 'hash(p)'
/// NOTE: The zcash specification defines their own methodologies for generating spending keys  which are the spiritual successor to the
/// double-spending protection serial numbers provide
pub struct TransactionSerialNumber<F: PrimeField> {
    value: FpVar<F>,
}
impl<F> TransactionSerialNumber<F>
where
    F: PrimeField,
{
    pub fn new(p: FpVar<F>) -> Self {
        let mut holder = vec![];
        let unit_var: UnitVar<F> = UnitVar::default();
        holder.extend_from_slice(&p.to_bytes().unwrap());

        let sn = Sha256Gadget::evaluate(&unit_var, &holder)
            .unwrap()
            .0
            .to_constraint_field()
            .unwrap()[0]
            .to_owned();
        Self { value: sn }
    }
    pub fn sn(&self) -> FpVar<F> {
        self.value.clone()
    }
}
pub struct Transaction<F: PrimeField> {
    transaction_id: FpVar<F>, // TODO: When we add a blockchain structure it should keep track of all previously used transaction_ids to enforce uniqueness
    value: FpVar<F>,
    sender_address: Address<F>, // built from the spending key of the sender
    receiver_address: Address<F>, // built from the spending key of the receiver
    serial_number: TransactionSerialNumber<F>,
}
// TODO: Add support for transaction splitting
impl<F> Transaction<F>
where
    F: PrimeField,
{
    pub fn new(
        transaction_id: FpVar<F>,
        value: FpVar<F>,
        sender_address_secret: FpVar<F>,
        receiver_address_secret: FpVar<F>,
        sn_secret: FpVar<F>,
    ) -> Self {
        Self {
            transaction_id,
            value,
            sender_address: Address::new(sender_address_secret),
            receiver_address: Address::new(receiver_address_secret),
            serial_number: TransactionSerialNumber::new(sn_secret),
        }
    }
    pub fn transaction_id(&self) -> FpVar<F> {
        self.transaction_id.clone()
    }
    pub fn value(&self) -> FpVar<F> {
        self.value.clone()
    }
    pub fn sender_address(&self) -> Address<F> {
        self.sender_address.clone()
    }
    pub fn receiver_address(&self) -> Address<F> {
        self.receiver_address.clone()
    }
    pub fn serial_number(&self) -> FpVar<F> {
        self.serial_number.sn()
    }
    pub fn to_vec(&self) -> Vec<FpVar<F>> {
        vec![
            self.transaction_id(),
            self.value(),
            self.sender_address().public_key(),
            self.sender_address().secret_key(),
            self.receiver_address().public_key(),
            self.receiver_address().secret_key(),
            self.serial_number(),
        ]
    }
    pub fn root(&self) -> FpVar<F> {
        let cs = ConstraintSystem::<F>::new_ref();
        for (idx, _) in self.to_vec().iter().enumerate() {
            // Verify the chosen leaf
            let is_valid = MerkleTreeGadget::generate_proof_and_validate(
                &self.to_vec(),
                cs.clone(),
                vec![idx],
            );
            if !is_valid {
                panic!("Cannot get root hash if leaves are not all valid");
            }
        }
        MerkleTreeGadget::create_root_hash(self.to_vec(), cs)
    }
    /// This assumes a single split where the remainder is given back to the original person
    pub fn split_transaction(
        &self,
        split_values: Vec<FpVar<F>>, // The values to split into
        new_receiver_addresses: Vec<Address<F>>, // The new receiver addresses for each split
        sender_address_secret: FpVar<F>, // Sender's secret key
    ) -> Vec<Self> {
        // Ensure that the split values sum up to the original transaction value
        let cs = ConstraintSystem::<F>::new_ref();
        let mut total_split_value = FpVar::<F>::zero();

        for split_value in &split_values {
            total_split_value += split_value;
        }

        // Enforce that the sum of the split values equals the original transaction value
        total_split_value.enforce_equal(&self.value).unwrap();

        // Create the split transactions
        let mut split_transactions = Vec::new();

        for (i, split_value) in split_values.into_iter().enumerate() {
            // Generate a new transaction ID, based on the original ID and the index
            let new_transaction_id = FpVar::<F>::new_input(cs.clone(), || {
                Ok(F::from(i as u64)) // Unique ID based on index for simplicity
            })
            .unwrap();

            // Create a new serial number for the split transaction
            let mut rng = thread_rng();
            let new_serial_number = TransactionSerialNumber::new(
                FpVar::new_input(cs.clone(), || Ok(F::rand(&mut rng))).unwrap(),
            );

            // Generate the new split transaction
            let split_transaction = Transaction {
                transaction_id: new_transaction_id,
                value: split_value,
                sender_address: Address::new(sender_address_secret.clone()), // Sender remains the same
                receiver_address: new_receiver_addresses[i].clone(), // New receiver address for this split
                serial_number: new_serial_number,
            };

            split_transactions.push(split_transaction);
        }

        split_transactions
    }
}
pub struct Blockchain<F: PrimeField> {
    inner: HashMap<SN<F>, ROOT<F>>, // Use HashMap with serial numbers as keys
}

impl<F> Blockchain<F>
where
    F: PrimeField,
{
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn append_transaction(&mut self, root: FpVar<F>, serial_number: FpVar<F>) {
        // Convert FpVar<F> to concrete values
        let root_value = root.value().unwrap();
        let sn_value = serial_number.value().unwrap();
        println!("Serial number of new transaction: {:?}", sn_value.clone());
        // Check if the serial number is already in the HashMap
        if self.inner.contains_key(&sn_value) {
            panic!("The serial number is already in the blockchain!");
        }

        // Insert the transaction into the HashMap
        self.inner.insert(sn_value, root_value);
    }
    pub fn dump_transactions(&self) {
        println!("Blockchain Transactions:");
        println!("========================");

        for (serial_number, root) in &self.inner {
            println!("Transaction:");
            println!("  Serial Number: {:?}", serial_number);
            println!("  Root: {:?}", root);
        }

        println!("========================");
    }
}
impl<F> Default for Blockchain<F>
where
    F: PrimeField,
{
    fn default() -> Self {
        Self::new()
    }
}
impl<F: PrimeField> Display for Blockchain<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (serial_number, root) in &self.inner {
            writeln!(f, "Transaction:")?;
            writeln!(f, "  Serial Number: {:?}", serial_number)?;
            writeln!(f, "  Root: {:?}", root)?;
        }
        Ok(())
    }
}
