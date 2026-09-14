use crate::types::{BlockChainExpectedException, BlockExpectedException};
use ethrex_common::Address;
use serde::{Deserialize, Deserializer};

/// An EIP-8141 address field that may be deliberately empty: a frame targeting
/// `tx.sender` implicitly, or the signer of an `ARBITRARY` signature entry,
/// which the protocol assigns no signer. Fixtures write those as `"0x"` rather
/// than omitting the key, which a plain `Option<Address>` rejects.
pub fn deserialize_empty_as_none_address<'de, D>(
    deserializer: D,
) -> Result<Option<Address>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Option<String> = Option::deserialize(deserializer)?;
    let Some(raw) = raw else { return Ok(None) };
    let digits = raw.strip_prefix("0x").unwrap_or(&raw);
    if digits.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(digits).map_err(serde::de::Error::custom)?;
    if bytes.len() != Address::len_bytes() {
        return Err(serde::de::Error::custom(format!(
            "expected a 20-byte address, got {} bytes",
            bytes.len()
        )));
    }
    Ok(Some(Address::from_slice(&bytes)))
}

pub const SENDER_NOT_EOA_REGEX: &str = "Sender account .* shouldn't be a contract";
pub const PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS_REGEX: &str =
    "Priority fee .* is greater than max fee per gas .*";

pub fn deserialize_block_expected_exception<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<BlockChainExpectedException>>, D::Error>
where
    D: Deserializer<'de>,
{
    let option: Option<String> = Option::deserialize(deserializer)?;

    if let Some(value) = option {
        let exceptions = value
            .split('|')
            .map(|s| match s.trim() {
                "TransactionException.INITCODE_SIZE_EXCEEDED" => {
                    BlockChainExpectedException::TxtException("Initcode size exceeded".to_string())
                }
                "TransactionException.NONCE_IS_MAX" => {
                    BlockChainExpectedException::TxtException("Nonce is max".to_string())
                }
                "TransactionException.TYPE_3_TX_BLOB_COUNT_EXCEEDED" => {
                    BlockChainExpectedException::TxtException("Blob count exceeded".to_string())
                }
                "TransactionException.TYPE_3_TX_ZERO_BLOBS" => {
                    BlockChainExpectedException::TxtException(
                        "Type 3 transaction without blobs".to_string(),
                    )
                }
                "TransactionException.TYPE_3_TX_CONTRACT_CREATION" => {
                    BlockChainExpectedException::RLPException
                }
                "TransactionException.TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH" => {
                    BlockChainExpectedException::TxtException(
                        "Invalid blob versioned hash".to_string(),
                    )
                }
                "TransactionException.INTRINSIC_GAS_TOO_LOW" => {
                    BlockChainExpectedException::TxtException("Transaction gas limit lower than the minimum gas cost to execute the transaction".to_string())
                }
                "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS" => {
                    BlockChainExpectedException::TxtException(
                        "Insufficient account funds".to_string(),
                    )
                }
                "TransactionException.SENDER_NOT_EOA" => {
                    BlockChainExpectedException::TxtException(SENDER_NOT_EOA_REGEX.to_string())
                }
                "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS" => {
                    BlockChainExpectedException::TxtException(
                        PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS_REGEX.to_string(),
                    )
                }
                "TransactionException.GAS_ALLOWANCE_EXCEEDED" => {
                    BlockChainExpectedException::TxtException("Gas allowance exceeded".to_string())
                }
                "TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS" => {
                    BlockChainExpectedException::TxtException(
                        "Insufficient max fee per gas".to_string(),
                    )
                }
                "TransactionException.RLP_INVALID_VALUE" => {
                    BlockChainExpectedException::TxtException("RLP invalid value".to_string())
                }
                "TransactionException.GASLIMIT_PRICE_PRODUCT_OVERFLOW" => {
                    BlockChainExpectedException::TxtException(
                        "Gas limit price product overflow".to_string(),
                    )
                }
                "TransactionException.TYPE_3_TX_PRE_FORK" => {
                    BlockChainExpectedException::TxtException(
                        "Type 3 transactions are not supported before the Cancun fork".to_string(),
                    )
                }
                "TransactionException.TYPE_4_TX_CONTRACT_CREATION" => {
                    BlockChainExpectedException::RLPException
                }
                "TransactionException.INSUFFICIENT_MAX_FEE_PER_BLOB_GAS" => {
                    BlockChainExpectedException::TxtException(
                        "Insufficient max fee per blob gas".to_string(),
                    )
                }
                "TransactionException.GAS_LIMIT_EXCEEDS_MAXIMUM" => {
                    BlockChainExpectedException::TxtException(
                        "Transaction gas limit exceeds maximum.".to_string(),
                    )
                }
                "TransactionException.INVALID_SIGNATURE_VRS"
                | "TransactionException.TYPE_6_INVALID_SIGNATURE" => {
                    BlockChainExpectedException::InvalidSignature
                }
                // A fee field of 2**256 or more on a type-0x06 transaction.
                // EIP-8141 bounds a frame transaction's fees below 2**256, matching
                // its `U256` fee fields, so the fixtures' 33-byte values do not fit
                // the fields; ethrex rejects such a transaction while decoding, which
                // is a legitimate way to reject it and the same shape as
                // `NONCE_IS_MAX` above.
                "TransactionException.GASPRICE_OVERFLOW"
                | "TransactionException.PRIORITY_OVERFLOW" => {
                    BlockChainExpectedException::FeeOverflow
                }
                "TransactionException.TYPE_6_INVALID_FRAME_FORMAT" => {
                    BlockChainExpectedException::InvalidFrameFormat
                }
                "BlockException.RLP_STRUCTURES_ENCODING" => {
                    BlockChainExpectedException::RLPException
                }
                "BlockException.INCORRECT_BLOB_GAS_USED" => {
                    BlockChainExpectedException::BlockException(
                        BlockExpectedException::IncorrectBlobGasUsed,
                    )
                }
                "BlockException.BLOB_GAS_USED_ABOVE_LIMIT" => {
                    BlockChainExpectedException::BlockException(
                        BlockExpectedException::BlobGasUsedAboveLimit,
                    )
                }
                "BlockException.INCORRECT_EXCESS_BLOB_GAS" => {
                    BlockChainExpectedException::BlockException(
                        BlockExpectedException::IncorrectExcessBlobGas,
                    )
                }
                "BlockException.INCORRECT_BLOCK_FORMAT" => {
                    BlockChainExpectedException::BlockException(
                        BlockExpectedException::IncorrectBlockFormat,
                    )
                }
                "BlockException.INVALID_REQUESTS" => BlockChainExpectedException::BlockException(
                    BlockExpectedException::InvalidRequest,
                ),
                "BlockException.SYSTEM_CONTRACT_CALL_FAILED" => {
                    BlockChainExpectedException::BlockException(
                        BlockExpectedException::SystemContractCallFailed,
                    )
                }
                "BlockException.RLP_BLOCK_LIMIT_EXCEEDED" => BlockChainExpectedException::BlockException(
                    BlockExpectedException::RlpBlockLimitExceeded,
                ),
                _ => BlockChainExpectedException::Other,
            })
            .collect();

        Ok(Some(exceptions))
    } else {
        Ok(None)
    }
}
