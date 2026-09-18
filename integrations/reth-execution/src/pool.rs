// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed admission boundary for the real Reth pool; deposits are not pool transactions.
use crate::{BlochNodeBlock, BlochRethTransaction};
use alloy_consensus::transaction::Recovered;
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use bloch_l2_evm::{decode_signed_transaction, transactions::MAX_RAW_TRANSACTION_BYTES, ChainSpec};
use reth_primitives_traits::SealedBlock;
use reth_transaction_pool::{
    error::{InvalidPoolTransactionError, PoolTransactionError},
    validate::TransactionValidationOutcome,
    EthBlobTransactionSidecar, EthPooledTransaction, TransactionOrigin, TransactionValidator,
};

/// Permanent admission failure; the wrapped chain-aware validator is never called.
#[derive(Debug)]
pub struct BlochPoolError(String);
impl core::fmt::Display for BlochPoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}
impl core::error::Error for BlochPoolError {}
impl PoolTransactionError for BlochPoolError {
    fn is_bad_transaction(&self) -> bool {
        true
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
/// Authenticate canonical signed bytes and reconstruct every pooled cache field.
/// Native decoding happens after core authentication, and ignores external sender/hash caches.
pub fn pooled_from_raw(spec: &ChainSpec, raw: &[u8]) -> Result<EthPooledTransaction, BlochPoolError> {
    let authenticated = decode_signed_transaction(spec, raw).map_err(|e| BlochPoolError(e.to_string()))?;
    let mut bytes = raw;
    let transaction = BlochRethTransaction::decode_2718(&mut bytes).map_err(|e| BlochPoolError(e.to_string()))?;
    if !bytes.is_empty() {
        return Err(BlochPoolError("trailing transaction bytes".into()));
    }
    Ok(EthPooledTransaction::new(
        Recovered::new_unchecked(transaction, authenticated.sender()),
        raw.len(),
    ))
}
/// Reauthenticates candidates before the upstream validator checks state-dependent rules.
///
/// `inner` is trusted configuration and must use this same chain specification,
/// canonical provider snapshots, enabled balance checks, and disabled blob/7702
/// admission. The generic trait exposes no way to inspect its configuration.
#[derive(Debug, Clone)]
pub struct BlochTransactionValidator<V> {
    spec: ChainSpec,
    inner: V,
}
impl<V> BlochTransactionValidator<V> {
    /// Bind the portable signed boundary to a same-chain upstream validator.
    pub fn new(spec: &ChainSpec, inner: V) -> Self {
        Self {
            spec: spec.clone(),
            inner,
        }
    }
}
impl<V> TransactionValidator for BlochTransactionValidator<V>
where
    V: TransactionValidator<Transaction = EthPooledTransaction, Block = BlochNodeBlock>,
{
    type Transaction = EthPooledTransaction;
    type Block = BlochNodeBlock;
    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: EthPooledTransaction,
    ) -> TransactionValidationOutcome<EthPooledTransaction> {
        // Measure canonical bytes, never the attacker-controlled encoded_length cache.
        let error = if transaction.transaction.encode_2718_len() > MAX_RAW_TRANSACTION_BYTES {
            Some(BlochPoolError("signed transaction too large".into()))
        } else if !matches!(transaction.blob_sidecar, EthBlobTransactionSidecar::None) {
            Some(BlochPoolError("Bloch pool does not accept blob sidecars".into()))
        } else {
            None
        };
        if let Some(error) = error {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::Other(Box::new(error)),
            );
        }
        let raw = transaction.transaction.encoded_2718();
        match pooled_from_raw(&self.spec, &raw) {
            Ok(rebuilt) => self.inner.validate_transaction(origin, rebuilt).await,
            Err(error) => {
                TransactionValidationOutcome::Invalid(transaction, InvalidPoolTransactionError::Other(Box::new(error)))
            }
        }
    }
    fn on_new_head_block(&self, block: &SealedBlock<BlochNodeBlock>) {
        self.inner.on_new_head_block(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{EthereumTxEnvelope, SignableTransaction, Signed, TxEip1559};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
    use k256::ecdsa::SigningKey;
    use std::{
        future::Future,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        task::{Context, Poll, Waker},
    };
    #[derive(Debug, Clone, Default)]
    struct Observe {
        calls: Arc<AtomicUsize>,
        heads: Arc<AtomicUsize>,
        last: Arc<Mutex<Option<EthPooledTransaction>>>,
    }
    impl TransactionValidator for Observe {
        type Transaction = EthPooledTransaction;
        type Block = BlochNodeBlock;
        async fn validate_transaction(
            &self,
            _: TransactionOrigin,
            tx: EthPooledTransaction,
        ) -> TransactionValidationOutcome<EthPooledTransaction> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().unwrap() = Some(tx.clone());
            TransactionValidationOutcome::Invalid(
                tx,
                InvalidPoolTransactionError::Other(Box::new(BlochPoolError("test observer".into()))),
            )
        }
        fn on_new_head_block(&self, _: &SealedBlock<BlochNodeBlock>) {
            self.heads.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn ready<F: Future>(future: F) -> F::Output {
        match Box::pin(future).as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("observer should be immediately ready"),
        }
    }
    fn signed(spec: &ChainSpec) -> BlochRethTransaction {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let tx = TxEip1559 {
            chain_id: spec.chain_id,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            to: TxKind::Call(Address::repeat_byte(3)),
            ..Default::default()
        };
        let signature: Signature = key
            .sign_prehash_recoverable(tx.signature_hash().as_slice())
            .unwrap()
            .into();
        tx.into_signed(signature).into()
    }
    #[test]
    fn canonical_admission_rebuilds_sender_hash_cost_and_length() {
        let spec = ChainSpec::testnet();
        let tx = signed(&spec);
        let raw = tx.encoded_2718();
        let expected = pooled_from_raw(&spec, &raw).unwrap();
        let EthereumTxEnvelope::Eip1559(signed) = tx else {
            panic!("1559")
        };
        let (tx, signature, _) = signed.into_parts();
        let forged: BlochRethTransaction = Signed::new_unchecked(tx, signature, B256::repeat_byte(99)).into();
        let mut candidate = EthPooledTransaction::new(Recovered::new_unchecked(forged, Address::ZERO), 1);
        candidate.cost = U256::ZERO;
        let observer = Observe::default();
        let validator = BlochTransactionValidator::new(&spec, observer.clone());
        ready(validator.validate_transaction(TransactionOrigin::External, candidate));
        assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
        let observed = observer.last.lock().unwrap();
        let actual = observed.as_ref().unwrap();
        assert_eq!(actual.transaction.signer(), expected.transaction.signer());
        assert_eq!(actual.transaction.tx_hash(), expected.transaction.tx_hash());
        assert_eq!(actual.cost, expected.cost);
        assert_eq!(actual.encoded_length, raw.len());
        assert_eq!(actual.transaction.encoded_2718(), raw);
    }
    #[test]
    fn malformed_wrong_chain_and_oversized_inputs_never_delegate() {
        let spec = ChainSpec::testnet();
        let observer = Observe::default();
        let validator = BlochTransactionValidator::new(&spec, observer.clone());
        let mut foreign = spec.clone();
        foreign.chain_id += 1;
        let wrong = EthPooledTransaction::new(Recovered::new_unchecked(signed(&foreign), Address::ZERO), 0);
        assert!(ready(validator.validate_transaction(TransactionOrigin::External, wrong)).is_invalid());
        let oversized: BlochRethTransaction = TxEip1559 {
            input: Bytes::from(vec![0; MAX_RAW_TRANSACTION_BYTES + 1]),
            ..Default::default()
        }
        .into_signed(Signature::new(U256::from(1), U256::from(1), false))
        .into();
        let mut oversized = EthPooledTransaction::new(Recovered::new_unchecked(oversized, Address::ZERO), 0);
        oversized.encoded_length = 0;
        assert!(ready(validator.validate_transaction(TransactionOrigin::External, oversized)).is_invalid());
        let mut sidecar = pooled_from_raw(&spec, &signed(&spec).encoded_2718()).unwrap();
        sidecar.blob_sidecar = EthBlobTransactionSidecar::Missing;
        assert!(ready(validator.validate_transaction(TransactionOrigin::External, sidecar)).is_invalid());
        assert_eq!(observer.calls.load(Ordering::SeqCst), 0);
        assert!(pooled_from_raw(&spec, &[2]).is_err());
        let mut trailing = signed(&spec).encoded_2718();
        trailing.push(0);
        assert!(pooled_from_raw(&spec, &trailing).is_err());
    }
    #[test]
    fn canonical_head_notifications_are_forwarded() {
        let spec = ChainSpec::testnet();
        let observer = Observe::default();
        let validator = BlochTransactionValidator::new(&spec, observer.clone());
        let state = bloch_l2_evm::node_execution::genesis_v2(&spec, 0).unwrap();
        let header = bloch_l2_evm::node_execution::node_head(&spec, B256::repeat_byte(3), &state).unwrap();
        let block = SealedBlock::seal_slow(BlochNodeBlock {
            header: crate::BlochNodeHeader(header),
            body: crate::BlochNodeBody::try_from_core(Default::default()).unwrap(),
        });
        validator.on_new_head_block(&block);
        assert_eq!(observer.heads.load(Ordering::SeqCst), 1);
    }
}
