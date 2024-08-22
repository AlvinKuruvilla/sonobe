use ark_bn254::Fr;
use ark_std::rand::{thread_rng, Rng};
use ark_std::UniformRand;
use std::collections::HashMap;

#[derive(Clone)]
// TODO: This is aan outdated type I think, transaction.rs will likely have a type we will use from now on
// TODO: Eventually all of these extra types and example programs should be removed once we get our bearings with the workflow
pub struct SpendKey {
    sn: Fr,
    // The value associated with a coin
    value: i32,
    is_spent: bool,
}
impl SpendKey {
    pub fn sn(&self) -> Fr {
        self.sn
    }
    pub fn is_spent(&self) -> bool {
        self.is_spent
    }
    pub fn new(key: Fr, spent: bool, val: i32) -> Self {
        Self {
            sn: key,
            value: val,
            is_spent: spent,
        }
    }
    pub fn value(&self) -> i32 {
        self.value
    }
    pub fn from_random() -> Self {
        let mut rng = ark_std::test_rng();
        let mut value_rng = thread_rng();
        Self {
            sn: Fr::rand(&mut rng),
            value: value_rng.gen_range(i32::MIN..i32::MAX),
            is_spent: true,
        }
    }
    pub fn to_fr(&self) -> Fr {
        self.sn + Fr::from(self.value) + Fr::from(self.is_spent as u64)
    }
}
#[derive(Clone)]
pub struct SpendKeyMap {
    inner: HashMap<usize, SpendKey>,
}
impl SpendKeyMap {
    pub fn new(data: Vec<(Fr, Fr, Fr, i32)>) -> Self {
        let mut map: HashMap<usize, SpendKey> = HashMap::new();
        for (mut idx, element) in data.into_iter().enumerate() {
            map.insert(idx, SpendKey::new(element.1, false, element.3));
            idx += 1;
        }
        Self { inner: map }
    }
    pub fn inner(&self) -> HashMap<usize, SpendKey> {
        self.inner.clone()
    }
    pub fn spend_coin(mut self, coin_id: usize) {
        self.inner.get_mut(&coin_id).unwrap().is_spent = true;
    }
    pub fn spend_coins(&mut self, coin_ids: Vec<usize>) {
        for id in coin_ids {
            self.inner.get_mut(&id).unwrap().is_spent = true;
        }
    }
    pub fn find_biggest_id(&self) -> usize {
        let mut ids: Vec<&usize> = self.inner.keys().collect();
        ids.sort();
        ids[ids.len() - 1].to_owned()
    }
    pub fn all_serial_numbers(&self) -> Vec<Fr> {
        self.inner.values().map(|sk| sk.sn()).collect()
    }
    pub fn split_coin(&mut self, coin_id: usize, key1: SpendKey, key2: SpendKey) {
        let original_value = self.inner.get(&coin_id).unwrap().value;
        assert_eq!(key1.value + key2.value, original_value);
        self.inner.remove(&coin_id);
        self.inner.insert(self.find_biggest_id() + 1, key1);
        self.inner.insert(self.find_biggest_id() + 2, key2);
    }
}
