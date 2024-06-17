use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, UnparsedPublicKey, ED25519};
use rand::Rng;
use crate::types::address::Address;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Transaction {
  sender: Address,
  receiver: Address,
  value: u64,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SignedTransaction {
  transaction: Transaction,
  signature: Vec<u8>,
  public_key: Vec<u8>,
}

/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    let encoded_transaction = bincode::serialize(t).unwrap();
    key.sign(&encoded_transaction)
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &Transaction, public_key: &[u8], signature: &[u8]) -> bool {
    let encoded_transaction = bincode::serialize(t).unwrap();
    let public_key = UnparsedPublicKey::new(&ED25519, public_key);
    public_key.verify(&encoded_transaction, signature).is_ok()
}

#[cfg(any(test, test_utilities))]
pub fn generate_random_transaction() -> Transaction {
    let mut rng = rand::thread_rng();
    Transaction {
      sender: Address::from(&rng.gen::<[u8; 20]>()),
      receiver: Address::from(&rng.gen::<[u8; 20]>()),
      value: rng.gen(),
    }
}

// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. BEFORE TEST

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::key_pair;
    use ring::signature::KeyPair;


    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, key.public_key().as_ref(), signature.as_ref()));
    }
    #[test]
    fn sign_verify_two() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        let key_2 = key_pair::random();
        let t_2 = generate_random_transaction();
        assert!(!verify(&t_2, key.public_key().as_ref(), signature.as_ref()));
        assert!(!verify(&t, key_2.public_key().as_ref(), signature.as_ref()));
    }
}

// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. AFTER TEST