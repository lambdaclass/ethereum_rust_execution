use std::ops::AddAssign;

use crate::serde_utils;
#[cfg(feature = "c-kzg")]
use crate::types::Fork;
use crate::types::constants::VERSIONED_HASH_VERSION_KZG;
use crate::{Bytes, H256};

use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "c-kzg")]
use super::BYTES_PER_CELL;
use super::{BYTES_PER_BLOB, CELLS_PER_EXT_BLOB, SAFE_BYTES_PER_BLOB};
#[cfg(feature = "c-kzg")]
use super::{MAX_BLOB_COUNT, MAX_BLOB_COUNT_ELECTRA};

pub type Bytes48 = [u8; 48];
pub type Blob = [u8; BYTES_PER_BLOB];
pub type Commitment = Bytes48;
pub type Proof = Bytes48;
pub type BlobTuple = (Box<Blob>, Commitment, Vec<Proof>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
/// Struct containing all the blobs for a blob transaction, along with the corresponding commitments and proofs
pub struct BlobsBundle {
    #[serde(with = "serde_utils::blob::vec")]
    pub blobs: Vec<Blob>,
    #[serde(with = "serde_utils::bytes48::vec")]
    pub commitments: Vec<Commitment>,
    #[serde(with = "serde_utils::bytes48::vec")]
    pub proofs: Vec<Proof>,
    #[serde(skip, default)]
    pub version: u8,
}

pub fn blob_from_bytes(bytes: Bytes) -> Result<Blob, BlobsBundleError> {
    // This functions moved from `l2/utils/eth_client/transaction.rs`
    // We set the first byte of every 32-bytes chunk to 0x00
    // so it's always under the field module.
    if bytes.len() > SAFE_BYTES_PER_BLOB {
        return Err(BlobsBundleError::BlobDataInvalidBytesLength);
    }

    let mut buf = [0u8; BYTES_PER_BLOB];
    buf[..(bytes.len() * 32).div_ceil(31)].copy_from_slice(
        &bytes
            .chunks(31)
            .map(|x| [&[0x00], x].concat())
            .collect::<Vec<_>>()
            .concat(),
    );

    Ok(buf)
}

pub fn bytes_from_blob(blob: Bytes) -> [u8; SAFE_BYTES_PER_BLOB] {
    let mut buf = [0u8; SAFE_BYTES_PER_BLOB];
    buf.copy_from_slice(
        &blob
            .chunks(32)
            .map(|x| x[1..].to_vec())
            .collect::<Vec<_>>()
            .concat(),
    );

    buf
}

pub fn kzg_commitment_to_versioned_hash(data: &Commitment) -> H256 {
    use sha2::{Digest, Sha256};
    let mut versioned_hash: [u8; 32] = Sha256::digest(data).into();
    versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
    versioned_hash.into()
}

impl BlobsBundle {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty() && self.commitments.is_empty() && self.proofs.is_empty()
    }

    // In the future we might want to provide a new method that calculates the commitments and proofs using the following.
    #[cfg(feature = "c-kzg")]
    pub fn create_from_blobs(
        blobs: &Vec<Blob>,
        wrapper_version: Option<u8>,
    ) -> Result<Self, BlobsBundleError> {
        use ethrex_crypto::kzg::{
            blob_to_commitment_and_cell_proofs, blob_to_kzg_commitment_and_proof,
        };
        let mut commitments = Vec::new();
        let mut proofs = Vec::new();

        // Populate the commitments and proofs
        for blob in blobs {
            if wrapper_version.unwrap_or(0) == 0 {
                let (commitment, proof) = blob_to_kzg_commitment_and_proof(blob)?;
                commitments.push(commitment);
                proofs.push(proof);
            } else {
                let (commitment, cell_proofs) = blob_to_commitment_and_cell_proofs(blob)?;
                commitments.push(commitment);
                proofs.extend(cell_proofs);
            }
        }

        Ok(Self {
            blobs: blobs.clone(),
            commitments,
            proofs,
            version: wrapper_version.unwrap_or(0),
        })
    }

    pub fn generate_versioned_hashes(&self) -> Vec<H256> {
        self.commitments
            .iter()
            .map(kzg_commitment_to_versioned_hash)
            .collect()
    }

    /// Given an index returns all or nothing `BlobTuple` if either of the commitment, proof or
    /// blob is not found then it will return None instead of Partial data.
    pub fn get_blob_tuple_by_index(&self, index: usize) -> Option<BlobTuple> {
        let blob = Box::new(*self.blobs.get(index)?);
        let commitment = *self.commitments.get(index)?;
        let proofs = if self.version == 0 {
            vec![*self.proofs.get(index)?]
        } else {
            self.proofs.chunks(CELLS_PER_EXT_BLOB).nth(index)?.to_vec()
        };
        Some((blob, commitment, proofs))
    }

    /// Full blob bundle validation: structural checks + KZG cryptographic proof verification.
    #[cfg(feature = "c-kzg")]
    pub fn validate(
        &self,
        tx: &super::EIP4844Transaction,
        fork: super::Fork,
    ) -> Result<(), BlobsBundleError> {
        self.validate_cheap(tx, fork)?;
        self.verify_kzg_proofs()
    }

    /// Verifies KZG cryptographic proofs against the blobs and commitments.
    /// Dispatches to cell-proof or standard verification based on bundle version.
    #[cfg(feature = "c-kzg")]
    fn verify_kzg_proofs(&self) -> Result<(), BlobsBundleError> {
        let valid = if self.version != 0 {
            ethrex_crypto::kzg::verify_cell_kzg_proof_batch(
                &self.blobs,
                &self.commitments,
                &self.proofs,
            )?
        } else {
            ethrex_crypto::kzg::verify_kzg_proof_batch(
                &self.blobs,
                &self.commitments,
                &self.proofs,
            )?
        };
        if !valid {
            return Err(BlobsBundleError::BlobToCommitmentAndProofError);
        }
        Ok(())
    }

    /// Validates blob bundle structure without expensive KZG cryptographic verification.
    /// Used in P2P validation where full KZG is deferred to mempool insertion
    /// (after dedup check), avoiding redundant proof verification for the same
    /// blob tx received from multiple peers.
    #[cfg(feature = "c-kzg")]
    pub fn validate_cheap(
        &self,
        tx: &super::EIP4844Transaction,
        fork: super::Fork,
    ) -> Result<(), BlobsBundleError> {
        use super::CELLS_PER_EXT_BLOB;

        let max_blobs = max_blobs_per_block(fork);
        let blob_count = self.blobs.len();

        if blob_count > max_blobs {
            return Err(BlobsBundleError::MaxBlobsExceeded);
        }

        // EIP-7594: a single transaction may carry at most MAX_BLOB_COUNT (6) blobs,
        // independent of the higher per-block limit.
        if fork >= Fork::Osaka && blob_count > MAX_BLOB_COUNT {
            return Err(BlobsBundleError::MaxBlobsExceeded);
        }

        if blob_count == 0 {
            return Err(BlobsBundleError::BlobBundleEmptyError);
        }

        // Blob sidecar wrapper version: 0 = EIP-4844 blob proofs, 1 = EIP-7594 cell proofs.
        // The sidecar is a mempool/propagation-only artifact (never included in a block) and
        // both formats are cryptographically verifiable at any fork.
        //
        // Acceptance criteria:
        //   - pre-Osaka: accept BOTH v0 and v1. Peers are migrating to cell proofs at
        //     different times (e.g. post go-ethereum#35191 geth sends v1 even pre-Osaka,
        //     while older peers still send v0), so rejecting either would needlessly
        //     disconnect otherwise-valid peers.
        //   - Osaka+: only v1 (cell proofs) is valid.
        let version_ok = if fork >= Fork::Osaka {
            self.version == 1
        } else {
            self.version <= 1
        };
        if !version_ok {
            return Err(BlobsBundleError::InvalidBlobVersionForFork);
        }

        if blob_count != self.commitments.len()
            || (self.version == 0 && blob_count != self.proofs.len())
            || (self.version != 0 && blob_count * CELLS_PER_EXT_BLOB != self.proofs.len())
            || blob_count != tx.blob_versioned_hashes.len()
        {
            return Err(BlobsBundleError::BlobsBundleWrongLen);
        };

        self.validate_blob_commitment_hashes(&tx.blob_versioned_hashes)?;

        Ok(())
    }

    /// Structural validation for eth/72 elided bundles: blobs are omitted while
    /// commitments and cell proofs are present. Skips the empty-blob check and
    /// KZG proof verification (proofs are verified once cells are fetched via
    /// `GetCells`). The commitment list defines the blob count.
    #[cfg(feature = "c-kzg")]
    pub fn validate_elided(
        &self,
        tx: &super::EIP4844Transaction,
        fork: super::Fork,
    ) -> Result<(), BlobsBundleError> {
        use super::CELLS_PER_EXT_BLOB;

        let blob_count = self.commitments.len();

        if blob_count == 0 {
            return Err(BlobsBundleError::BlobBundleEmptyError);
        }
        if blob_count > max_blobs_per_block(fork) {
            return Err(BlobsBundleError::MaxBlobsExceeded);
        }
        // The elided form only exists on eth/72 (Osaka+) with the cell-proof wrapper.
        if self.version == 0 || fork < Fork::Osaka {
            return Err(BlobsBundleError::InvalidBlobVersionForFork);
        }
        if blob_count != tx.blob_versioned_hashes.len()
            || blob_count * CELLS_PER_EXT_BLOB != self.proofs.len()
        {
            return Err(BlobsBundleError::BlobsBundleWrongLen);
        }

        self.validate_blob_commitment_hashes(&tx.blob_versioned_hashes)
    }

    /// Return cells for the requested column indices (one inner Vec per blob).
    /// `column_mask` is a 128-bit bitmask; bit i set means column i is requested.
    /// Returns an error if blobs are missing (elided) or the c-kzg feature is absent.
    #[cfg(feature = "c-kzg")]
    pub fn cells_for_columns(
        &self,
        column_mask: u128,
    ) -> Result<Vec<Vec<[u8; BYTES_PER_CELL]>>, BlobsBundleError> {
        let mut result = Vec::with_capacity(self.blobs.len());
        for blob in &self.blobs {
            let all_cells = ethrex_crypto::kzg::compute_cells(blob)?;
            let mut blob_cells = vec![];
            for col in 0..128u32 {
                if (column_mask >> col) & 1 == 1 {
                    let cell = all_cells
                        .get(col as usize)
                        .ok_or(BlobsBundleError::BlobToCommitmentAndProofError)?;
                    blob_cells.push(*cell);
                }
            }
            result.push(blob_cells);
        }
        Ok(result)
    }

    pub fn validate_blob_commitment_hashes(
        &self,
        blob_versioned_hashes: &[H256],
    ) -> Result<(), BlobsBundleError> {
        if self.commitments.len() != blob_versioned_hashes.len() {
            return Err(BlobsBundleError::BlobVersionedHashesError);
        }
        for (commitment, blob_versioned_hash) in
            self.commitments.iter().zip(blob_versioned_hashes.iter())
        {
            if *blob_versioned_hash != kzg_commitment_to_versioned_hash(commitment) {
                return Err(BlobsBundleError::BlobVersionedHashesError);
            }
        }
        Ok(())
    }
}

impl RLPEncode for BlobsBundle {
    fn encode(&self, buf: &mut Vec<u8>) {
        let encoder = Encoder::new(buf);
        encoder
            .encode_field(&self.blobs)
            .encode_field(&self.commitments)
            .encode_field(&self.proofs)
            .encode_optional_field(&(self.version != 0).then_some(self.version))
            .finish();
    }
}

impl RLPDecode for BlobsBundle {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (blobs, decoder) = decoder.decode_field("blobs")?;
        let (commitments, decoder) = decoder.decode_field("commitments")?;
        let (proofs, decoder) = decoder.decode_field("proofs")?;
        let (version, decoder) = decoder.decode_optional_field();
        Ok((
            Self {
                blobs,
                commitments,
                proofs,
                version: version.unwrap_or_default(),
            },
            decoder.finish()?,
        ))
    }
}

impl AddAssign for BlobsBundle {
    fn add_assign(&mut self, rhs: Self) {
        self.blobs.extend_from_slice(&rhs.blobs);
        self.commitments.extend_from_slice(&rhs.commitments);
        self.proofs.extend_from_slice(&rhs.proofs);
        // Never downgrade: accumulator must track the highest version seen.
        self.version = self.version.max(rhs.version);
    }
}

#[cfg(feature = "c-kzg")]
fn max_blobs_per_block(fork: crate::types::Fork) -> usize {
    if fork >= crate::types::Fork::Prague {
        MAX_BLOB_COUNT_ELECTRA
    } else {
        MAX_BLOB_COUNT
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlobsBundleError {
    #[error("Blob data has an invalid length")]
    BlobDataInvalidBytesLength,
    #[error("Blob bundle is empty")]
    BlobBundleEmptyError,
    #[error("Blob versioned hashes and blobs bundle content length mismatch")]
    BlobsBundleWrongLen,
    #[error("Blob versioned hashes are incorrect")]
    BlobVersionedHashesError,
    #[error("Blob to commitment and proof generation error")]
    BlobToCommitmentAndProofError,
    #[error("Max blobs per block exceeded")]
    MaxBlobsExceeded,
    #[error("Invalid blob version for the current fork")]
    InvalidBlobVersionForFork,
    #[cfg(feature = "c-kzg")]
    #[error("KZG related error: {0}")]
    Kzg(#[from] ethrex_crypto::kzg::KzgError),
}

#[cfg(test)]
mod tests {
    mod shared {
        #[cfg(feature = "c-kzg")]
        pub fn convert_str_to_bytes48(s: &str) -> [u8; 48] {
            let bytes = hex::decode(s).expect("Invalid hex string");
            let mut array = [0u8; 48];
            array.copy_from_slice(&bytes[..48]);
            array
        }
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_valid_blobs_should_pass() {
        let blobs = vec!["Hello, world!".as_bytes(), "Goodbye, world!".as_bytes()]
            .into_iter()
            .map(|data| {
                crate::types::blobs_bundle::blob_from_bytes(data.into())
                    .expect("Failed to create blob")
            })
            .collect();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, None)
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Ok(())
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_valid_blobs_should_pass_on_osaka() {
        let blobs = vec!["Hello, world!".as_bytes(), "Goodbye, world!".as_bytes()]
            .into_iter()
            .map(|data| {
                crate::types::blobs_bundle::blob_from_bytes(data.into())
                    .expect("Failed to create blob")
            })
            .collect();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, Some(1))
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Osaka),
            Ok(())
        ));
    }

    // v1 (cell-proof) sidecars are accepted pre-Osaka (network is mid-migration to cell
    // proofs; some peers send v1 even before Osaka), but v0 (blob-proof) sidecars are
    // rejected on Osaka+.
    #[test]
    #[cfg(feature = "c-kzg")]
    fn v1_sidecar_is_accepted_pre_osaka() {
        let blobs = vec!["Hello, world!".as_bytes(), "Goodbye, world!".as_bytes()]
            .into_iter()
            .map(|data| {
                crate::types::blobs_bundle::blob_from_bytes(data.into())
                    .expect("Failed to create blob")
            })
            .collect();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, Some(1))
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Ok(())
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn v0_sidecar_is_rejected_on_osaka() {
        let blobs = vec!["Hello, world!".as_bytes(), "Goodbye, world!".as_bytes()]
            .into_iter()
            .map(|data| {
                crate::types::blobs_bundle::blob_from_bytes(data.into())
                    .expect("Failed to create blob")
            })
            .collect();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, Some(0))
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(!matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Osaka),
            Ok(())
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_invalid_proofs_should_fail() {
        // blob data taken from: https://etherscan.io/tx/0x02a623925c05c540a7633ffa4eb78474df826497faa81035c4168695656801a2#blobs, but with 0 size blobs
        let blobs_bundle = crate::types::BlobsBundle {
            blobs: vec![[0; crate::types::BYTES_PER_BLOB], [0; crate::types::BYTES_PER_BLOB]],
            commitments: vec!["b90289aabe0fcfb8db20a76b863ba90912d1d4d040cb7a156427d1c8cd5825b4d95eaeb221124782cc216960a3d01ec5",
                              "91189a03ce1fe1225fc5de41d502c3911c2b19596f9011ea5fca4bf311424e5f853c9c46fe026038036c766197af96a0"]
                              .into_iter()
                              .map(|s| {
                                  shared::convert_str_to_bytes48(s)
                              })
                              .collect(),
            proofs: vec!["b502263fc5e75b3587f4fb418e61c5d0f0c18980b4e00179326a65d082539a50c063507a0b028e2db10c55814acbe4e9",
                         "a29c43f6d05b7f15ab6f3e5004bd5f6b190165dc17e3d51fd06179b1e42c7aef50c145750d7c1cd1cd28357593bc7658"]
                            .into_iter()
                            .map(|s| {
                                shared::convert_str_to_bytes48(s)
                            })
                            .collect(),
                            version: 0,
        };

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes: vec![
                "01ec8054d05bfec80f49231c6e90528bbb826ccd1464c255f38004099c8918d9",
                "0180cb2dee9e6e016fabb5da4fb208555f5145c32895ccd13b26266d558cd77d",
            ]
            .into_iter()
            .map(|b| {
                let bytes = hex::decode(b).expect("Invalid hex string");
                crate::H256::from_slice(&bytes)
            })
            .collect::<Vec<crate::H256>>(),
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Err(crate::types::BlobsBundleError::BlobToCommitmentAndProofError)
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_incorrect_blobs_should_fail() {
        // blob data taken from: https://etherscan.io/tx/0x02a623925c05c540a7633ffa4eb78474df826497faa81035c4168695656801a2#blobs
        let blobs_bundle = crate::types::BlobsBundle {
            blobs: vec![[0; crate::types::BYTES_PER_BLOB], [0; crate::types::BYTES_PER_BLOB]],
            commitments: vec!["dead89aabe0fcfb8db20a76b863ba90912d1d4d040cb7a156427d1c8cd5825b4d95eaeb221124782cc216960a3d01ec5",
                              "91189a03ce1fe1225fc5de41d502c3911c2b19596f9011ea5fca4bf311424e5f853c9c46fe026038036c766197af96a0"]
                              .into_iter()
                              .map(|s| {
                                shared::convert_str_to_bytes48(s)
                              })
                              .collect(),
            proofs: vec!["b502263fc5e75b3587f4fb418e61c5d0f0c18980b4e00179326a65d082539a50c063507a0b028e2db10c55814acbe4e9",
                         "a29c43f6d05b7f15ab6f3e5004bd5f6b190165dc17e3d51fd06179b1e42c7aef50c145750d7c1cd1cd28357593bc7658"]
                         .into_iter()
                              .map(|s| {
                                shared::convert_str_to_bytes48(s)
                              })
                              .collect(),
                              version: 0,
        };

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes: vec![
                "01ec8054d05bfec80f49231c6e90528bbb826ccd1464c255f38004099c8918d9",
                "0180cb2dee9e6e016fabb5da4fb208555f5145c32895ccd13b26266d558cd77d",
            ]
            .into_iter()
            .map(|b| {
                let bytes = hex::decode(b).expect("Invalid hex string");
                crate::H256::from_slice(&bytes)
            })
            .collect::<Vec<crate::H256>>(),
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Err(crate::types::BlobsBundleError::BlobVersionedHashesError)
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_too_many_blobs_should_fail() {
        let blob = crate::types::blobs_bundle::blob_from_bytes("Im a Blob".as_bytes().into())
            .expect("Failed to create blob");
        let blobs =
            std::iter::repeat_n(blob, super::MAX_BLOB_COUNT_ELECTRA + 1).collect::<Vec<_>>();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, None)
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Prague),
            Err(crate::types::BlobsBundleError::MaxBlobsExceeded)
        ));
    }

    #[test]
    #[cfg(feature = "c-kzg")]
    fn transaction_with_version_0_blobs_should_fail_on_amsterdam() {
        // Version 0 blobs should be invalid on Amsterdam fork (which comes after Osaka)
        // The validation requires version 0 only on Osaka; Amsterdam >= Osaka so version 0 is rejected
        let blobs = vec!["Hello, world!".as_bytes(), "Goodbye, world!".as_bytes()]
            .into_iter()
            .map(|data| {
                crate::types::blobs_bundle::blob_from_bytes(data.into())
                    .expect("Failed to create blob")
            })
            .collect();

        let blobs_bundle = crate::types::BlobsBundle::create_from_blobs(&blobs, None)
            .expect("Failed to create blobs bundle");

        let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

        let tx = crate::types::transaction::EIP4844Transaction {
            nonce: 3,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            max_fee_per_blob_gas: 0.into(),
            gas: 15_000_000,
            to: crate::Address::from_low_u64_be(1), // Normal tx
            value: crate::U256::zero(),             // Value zero
            data: crate::Bytes::default(),          // No data
            access_list: Default::default(),        // No access list
            blob_versioned_hashes,
            ..Default::default()
        };

        assert!(matches!(
            blobs_bundle.validate(&tx, crate::types::Fork::Amsterdam),
            Err(crate::types::BlobsBundleError::InvalidBlobVersionForFork)
        ));
    }
}
