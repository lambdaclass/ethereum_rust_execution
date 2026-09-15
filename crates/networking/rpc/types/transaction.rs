use crate::utils::RpcErr;
use ethrex_common::{
    Address, H256, serde_utils,
    types::{
        BlockHash, BlockNumber, EIP1559Transaction, EIP2930Transaction, EIP7702Transaction,
        EnvelopeTxType, FeeTokenTransaction, FrameTransaction, LegacyTransaction,
        PrivilegedL2Transaction, Transaction, WrappedEIP4844Transaction,
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_rlp::{decode::RLPDecode, error::RLPDecodeError};
use serde::{Deserialize, Serialize};

#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransaction {
    #[serde(flatten)]
    pub tx: Transaction,
    #[serde(with = "serde_utils::u64::hex_str_opt")]
    block_number: Option<BlockNumber>,
    block_hash: Option<BlockHash>,
    from: Address,
    pub hash: H256,
    #[serde(with = "serde_utils::u64::hex_str_opt")]
    transaction_index: Option<u64>,
}

impl RpcTransaction {
    pub fn build(
        tx: Transaction,
        block_number: Option<BlockNumber>,
        block_hash: Option<BlockHash>,
        transaction_index: Option<usize>,
    ) -> Result<Self, RpcErr> {
        let from = tx.sender(&NativeCrypto)?;
        let hash = tx.hash(&NativeCrypto);
        let transaction_index = transaction_index.map(|n| n as u64);
        Ok(RpcTransaction {
            tx,
            block_number,
            block_hash,
            from,
            hash,
            transaction_index,
        })
    }

    /// Like [`RpcTransaction::build`] but with the sender provided by the
    /// caller. `eth_simulateV1` transactions carry zeroed signatures, so the
    /// sender cannot be recovered from them.
    pub fn build_with_sender(
        tx: Transaction,
        block_number: Option<BlockNumber>,
        block_hash: Option<BlockHash>,
        transaction_index: Option<usize>,
        from: Address,
    ) -> Self {
        let hash = tx.hash(&NativeCrypto);
        RpcTransaction {
            tx,
            block_number,
            block_hash,
            from,
            hash,
            transaction_index: transaction_index.map(|n| n as u64),
        }
    }
}

#[derive(Debug)]
pub enum SendRawTransactionRequest {
    Legacy(LegacyTransaction),
    EIP2930(EIP2930Transaction),
    EIP1559(EIP1559Transaction),
    EIP4844(WrappedEIP4844Transaction),
    EIP7702(EIP7702Transaction),
    PrivilegedL2(PrivilegedL2Transaction),
    FeeToken(FeeTokenTransaction),
    Frame(FrameTransaction),
}

impl SendRawTransactionRequest {
    pub fn to_transaction(&self) -> Transaction {
        match self {
            SendRawTransactionRequest::Legacy(t) => Transaction::LegacyTransaction(t.clone()),
            SendRawTransactionRequest::EIP1559(t) => Transaction::EIP1559Transaction(t.clone()),
            SendRawTransactionRequest::EIP2930(t) => Transaction::EIP2930Transaction(t.clone()),
            SendRawTransactionRequest::EIP4844(t) => Transaction::EIP4844Transaction(t.tx.clone()),
            SendRawTransactionRequest::EIP7702(t) => Transaction::EIP7702Transaction(t.clone()),
            SendRawTransactionRequest::PrivilegedL2(t) => {
                Transaction::PrivilegedL2Transaction(t.clone())
            }
            SendRawTransactionRequest::FeeToken(t) => Transaction::FeeTokenTransaction(t.clone()),
            SendRawTransactionRequest::Frame(t) => Transaction::FrameTransaction(t.clone()),
        }
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RLPDecodeError> {
        // Look at the first byte to check if it corresponds to a TransactionType
        match bytes.first() {
            // First byte is a valid TransactionType https://eips.ethereum.org/EIPS/eip-2718#transactiontype-only-goes-up-to-0x7f
            Some(tx_type) if *tx_type <= 0x7f => {
                // Decode tx based on type
                let tx_bytes = &bytes[1..];

                // `from_type_byte` is the single gate for valid envelope types: it rejects 0x00
                // (legacy is the bare-list branch below) and any unassigned type byte.
                match EnvelopeTxType::from_type_byte(*tx_type)? {
                    EnvelopeTxType::EIP2930 => {
                        EIP2930Transaction::decode(tx_bytes).map(SendRawTransactionRequest::EIP2930)
                    }
                    EnvelopeTxType::EIP1559 => {
                        EIP1559Transaction::decode(tx_bytes).map(SendRawTransactionRequest::EIP1559)
                    }
                    EnvelopeTxType::EIP4844 => WrappedEIP4844Transaction::decode(tx_bytes)
                        .map(SendRawTransactionRequest::EIP4844),
                    EnvelopeTxType::EIP7702 => {
                        EIP7702Transaction::decode(tx_bytes).map(SendRawTransactionRequest::EIP7702)
                    }
                    EnvelopeTxType::Frame => {
                        FrameTransaction::decode(tx_bytes).map(SendRawTransactionRequest::Frame)
                    }
                    EnvelopeTxType::FeeToken => FeeTokenTransaction::decode(tx_bytes)
                        .map(SendRawTransactionRequest::FeeToken),
                    EnvelopeTxType::Privileged => PrivilegedL2Transaction::decode(tx_bytes)
                        .map(SendRawTransactionRequest::PrivilegedL2),
                }
            }
            // LegacyTransaction
            _ => LegacyTransaction::decode(bytes).map(SendRawTransactionRequest::Legacy),
        }
    }
}
