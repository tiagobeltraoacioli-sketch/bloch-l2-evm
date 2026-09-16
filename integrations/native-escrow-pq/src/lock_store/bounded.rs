// SPDX-License-Identifier: AGPL-3.0-or-later
//! Enforce allocation bounds while decoding, before authentication or replay.
use alloy_primitives::{Address, B256};
use bloch_l2_evm::escrow::{LockIntent, Outpoint};
pub(super) use bloch_l2_evm::serde_bounded::vector;
use serde::{Deserialize, Deserializer};

// Keep the on-disk intent shape, but bound inputs before constructing LockIntent.
// Strict decoding also rejects misspelled fields rather than silently ignoring them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    network: B256,
    domain: B256,
    owner: B256,
    #[serde(deserialize_with = "vector::<_, _, 4096>")]
    inputs: Vec<Outpoint>,
    recipient: Address,
    amount: u64,
    fee: u64,
    change_owner: B256,
    nonce: u64,
}
pub(super) fn intent<'de, D: Deserializer<'de>>(deserializer: D) -> Result<LockIntent, D::Error> {
    let value = Intent::deserialize(deserializer)?;
    Ok(LockIntent {
        network: value.network,
        domain: value.domain,
        owner: value.owner,
        inputs: value.inputs,
        recipient: value.recipient,
        amount: value.amount,
        fee: value.fee,
        change_owner: value.change_owner,
        nonce: value.nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::value::{Error, SeqDeserializer};
    #[derive(Debug, Deserialize)]
    struct Small(#[serde(deserialize_with = "vector::<_, _, 2>")] Vec<u8>);
    #[test]
    fn accepts_boundary_rejects_excess_without_decoding_excess_value() {
        assert!(serde_json::from_str::<Small>("[]").unwrap().0.is_empty());
        assert_eq!(serde_json::from_str::<Small>("[1,2]").unwrap().0, vec![1, 2]);
        let error = serde_json::from_str::<Small>("[1,2,{}]").unwrap_err();
        assert!(error.to_string().contains("allocation limit"));
        let sequence = SeqDeserializer::<_, Error>::new(vec![1u8, 2, 3].into_iter());
        assert!(vector::<_, u8, 2>(sequence).is_err());
    }
}

#[cfg(test)]
mod record_tests {
    use super::*;
    use crate::lock_store::{OwnedLock, Record};
    fn lock() -> OwnedLock {
        OwnedLock {
            intent: LockIntent {
                network: B256::repeat_byte(1),
                domain: B256::repeat_byte(2),
                owner: B256::repeat_byte(3),
                inputs: vec![Outpoint {
                    txid: B256::repeat_byte(4),
                    vout: 0,
                }],
                recipient: Address::repeat_byte(5),
                amount: 600,
                fee: 10,
                change_owner: B256::repeat_byte(3),
                nonce: 0,
            },
            public_key: vec![0; 3749],
            signature: vec![0; 8192],
        }
    }
    #[test]
    fn persisted_authorization_fields_enforce_each_decode_boundary() {
        let mut original = lock();
        original.intent.inputs = vec![original.intent.inputs[0]; 4096];
        let encoded = serde_json::to_value(&original).unwrap();
        let recovered: OwnedLock = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(recovered.intent, original.intent);
        assert_eq!(recovered.public_key, original.public_key);
        assert_eq!(recovered.signature, original.signature);
        for field in ["public_key", "signature", "inputs"] {
            let mut excessive = encoded.clone();
            let array = if field == "inputs" {
                &mut excessive["intent"][field]
            } else {
                &mut excessive[field]
            };
            let first = array[0].clone();
            array.as_array_mut().unwrap().push(first);
            let error = serde_json::from_slice::<OwnedLock>(&serde_json::to_vec(&excessive).unwrap())
                .err()
                .unwrap();
            assert!(error.to_string().contains("allocation limit"), "{field}: {error}");
        }
    }
    #[test]
    fn record_rejects_extra_lock_before_decoding_nested_content() {
        let record = Record {
            version: 1,
            previous: B256::ZERO,
            after: B256::ZERO,
            locks: (0..64).map(|_| lock()).collect(),
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        assert_eq!(serde_json::from_slice::<Record>(&bytes).unwrap().locks.len(), 64);
        let mut value = serde_json::to_value(record).unwrap();
        value["locks"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"unexpected": [1, 2, 3]}));
        let error = serde_json::from_slice::<Record>(&serde_json::to_vec(&value).unwrap())
            .err()
            .unwrap();
        assert!(error.to_string().contains("allocation limit"));
    }
    #[test]
    fn misspelled_intent_fields_are_rejected_before_replay() {
        let mut value = serde_json::to_value(lock()).unwrap();
        value["intent"]["ammount"] = 700.into();
        let error = serde_json::from_value::<OwnedLock>(value).err().unwrap();
        assert!(error.to_string().contains("unknown field"));
    }
}
