use crate::peer_handler::DumpError;
use ethrex_common::{H256, H512, U256, types::AccountState, utils::keccak};
use ethrex_rlp::encode::RLPEncode;
use secp256k1::{PublicKey, SecretKey};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::error;

/// Computes the node_id from a public key (aka computes the Keccak256 hash of the given public key)
pub fn node_id(public_key: &H512) -> H256 {
    keccak(public_key)
}

pub fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn get_msg_expiration_from_seconds(seconds: u64) -> u64 {
    (SystemTime::now() + Duration::from_secs(seconds))
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn is_msg_expired(expiration: u64) -> bool {
    // this cast to a signed integer is needed as the rlp decoder doesn't take into account the sign
    // otherwise if a msg contains a negative expiration, it would pass since as it would wrap around the u64.
    (expiration as i64) < (current_unix_time() as i64)
}

pub fn public_key_from_signing_key(signer: &SecretKey) -> H512 {
    let public_key = PublicKey::from_secret_key(secp256k1::SECP256K1, signer);
    let encoded = public_key.serialize_uncompressed();
    H512::from_slice(&encoded[1..])
}

/// Deletes the snap folders needed for downloading the leaves during the initial
/// step of snap sync.
pub fn delete_leaves_folder(datadir: &Path) {
    // We ignore the errors because this can happen when the folders don't exist
    let _ = std::fs::remove_dir_all(get_account_state_snapshots_dir(datadir));
    let _ = std::fs::remove_dir_all(get_account_storages_snapshots_dir(datadir));
    let _ = std::fs::remove_dir_all(get_code_hashes_snapshots_dir(datadir));
    #[cfg(feature = "rocksdb")]
    {
        let _ = std::fs::remove_dir_all(get_rocksdb_temp_accounts_dir(datadir));
        let _ = std::fs::remove_dir_all(get_rocksdb_temp_storage_dir(datadir));
    };
}

pub fn get_account_storages_snapshots_dir(datadir: &Path) -> PathBuf {
    datadir.join("account_storages_snapshots")
}

pub fn get_account_state_snapshots_dir(datadir: &Path) -> PathBuf {
    datadir.join("account_state_snapshots")
}

pub fn get_rocksdb_temp_accounts_dir(datadir: &Path) -> PathBuf {
    datadir.join("temp_acc_dir")
}

pub fn get_rocksdb_temp_storage_dir(datadir: &Path) -> PathBuf {
    datadir.join("temp_storage_dir")
}

pub fn get_account_state_snapshot_file(directory: &Path, chunk_index: u64) -> PathBuf {
    directory.join(format!("account_state_chunk.rlp.{chunk_index}"))
}

pub fn get_account_storages_snapshot_file(directory: &Path, chunk_index: u64) -> PathBuf {
    directory.join(format!("account_storages_chunk.rlp.{chunk_index}"))
}

#[cfg(feature = "rocksdb")]
pub fn dump_accounts_to_rocks_db(
    path: &Path,
    mut contents: Vec<(H256, AccountState)>,
) -> Result<(), rocksdb::Error> {
    // This can happen sometimes during download, and the sst ingestion method
    // fails with empty chunk files
    if contents.is_empty() {
        return Ok(());
    }
    contents.sort_by_key(|(k, _)| *k);
    contents.dedup_by_key(|(k, _)| {
        let mut buf = [0u8; 32];
        buf[..32].copy_from_slice(&k.0);
        buf
    });
    let mut buffer: Vec<u8> = Vec::new();
    let writer_options = rocksdb::Options::default();
    let mut writer = rocksdb::SstFileWriter::create(&writer_options);
    writer.open(std::path::Path::new(&path))?;
    for (key, account) in contents {
        buffer.clear();
        account.encode(&mut buffer);
        writer.put(key.0.as_ref(), buffer.as_slice())?;
    }
    writer.finish()
}

#[cfg(feature = "rocksdb")]
pub fn dump_storages_to_rocks_db(
    path: &Path,
    mut contents: Vec<(H256, H256, U256)>,
) -> Result<(), rocksdb::Error> {
    // This can happen sometimes during download, and the sst ingestion method
    // fails with empty chunk files
    if contents.is_empty() {
        return Ok(());
    }
    contents.sort();
    contents.dedup_by_key(|(k0, k1, _)| {
        let mut buffer = [0_u8; 64];
        buffer[0..32].copy_from_slice(&k0.0);
        buffer[32..64].copy_from_slice(&k1.0);
        buffer
    });
    let writer_options = rocksdb::Options::default();
    let mut writer = rocksdb::SstFileWriter::create(&writer_options);
    let mut buffer_key = [0_u8; 64];
    let mut buffer_storage: Vec<u8> = Vec::new();
    writer.open(std::path::Path::new(&path))?;
    for (account, slot_hash, slot_value) in contents {
        buffer_key[0..32].copy_from_slice(&account.0);
        buffer_key[32..64].copy_from_slice(&slot_hash.0);
        buffer_storage.clear();
        slot_value.encode(&mut buffer_storage);
        writer.put(buffer_key.as_ref(), buffer_storage.as_slice())?;
    }
    writer.finish()
}

pub fn get_code_hashes_snapshots_dir(datadir: &Path) -> PathBuf {
    datadir.join("bytecode_hashes_snapshots")
}

pub fn get_code_hashes_snapshot_file(directory: &Path, chunk_index: u64) -> PathBuf {
    directory.join(format!("bytecode_hashes_chunk.rlp.{chunk_index}"))
}

pub fn dump_to_file(path: &Path, contents: Vec<u8>) -> Result<(), DumpError> {
    std::fs::write(path, &contents)
        .inspect_err(|err| error!(%err, ?path, "Failed to dump snapshot to file"))
        .map_err(|err| DumpError {
            path: path.to_path_buf(),
            error: err.kind(),
        })
}

pub fn dump_accounts_to_file(
    path: &Path,
    accounts: Vec<(H256, AccountState)>,
) -> Result<(), DumpError> {
    #[cfg(feature = "rocksdb")]
    return dump_accounts_to_rocks_db(path, accounts)
        .inspect_err(|err| error!("RocksDB SST write error: {err:?}"))
        .map_err(|_| DumpError {
            path: path.to_path_buf(),
            error: std::io::ErrorKind::Other,
        });
    #[cfg(not(feature = "rocksdb"))]
    dump_to_file(path, accounts.encode_to_vec())
}

/// Struct representing the storage slots of certain accounts that share the same storage root
pub struct AccountsWithStorage {
    /// Accounts with the same storage root
    pub accounts: Vec<H256>,
    /// All slots in the trie from the accounts
    pub storages: Vec<(H256, U256)>,
}

pub fn dump_storages_to_file(
    path: &Path,
    storages: Vec<AccountsWithStorage>,
) -> Result<(), DumpError> {
    #[cfg(feature = "rocksdb")]
    return dump_storages_to_rocks_db(
        path,
        storages
            .into_iter()
            .flat_map(|accounts_with_slots| {
                accounts_with_slots
                    .accounts
                    .into_iter()
                    .map(|hash| {
                        accounts_with_slots
                            .storages
                            .iter()
                            .map(move |(slot_hash, slot_value)| (hash, *slot_hash, *slot_value))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect::<Vec<_>>(),
    )
    .inspect_err(|err| error!("RocksDB SST write error: {err:?}"))
    .map_err(|_| DumpError {
        path: path.to_path_buf(),
        error: std::io::ErrorKind::Other,
    });

    #[cfg(not(feature = "rocksdb"))]
    dump_to_file(
        path,
        storages
            .into_iter()
            .map(|accounts_with_slots| (accounts_with_slots.accounts, accounts_with_slots.storages))
            .collect::<Vec<_>>()
            .encode_to_vec(),
    )
}

/// Computes the distance between two nodes according to the discv4/5 protocols
/// <https://github.com/ethereum/devp2p/blob/master/discv4.md#node-identities>
/// <https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md#nodes-records-and-distances>
pub fn distance(node_id_1: &H256, node_id_2: &H256) -> usize {
    let xor = node_id_1 ^ node_id_2;
    let distance = U256::from_big_endian(xor.as_bytes());
    distance.bits()
}

/// Decompresses the received public key
pub fn decompress_pubkey(pk: &PublicKey) -> H512 {
    let bytes = pk.serialize_uncompressed();
    debug_assert_eq!(bytes[0], 4);
    H512::from_slice(&bytes[1..])
}

/// Compresses the received public key
/// The received value is the uncompressed public key of a node, with the first byte omitted (0x04).
///
/// Lives here rather than under `rlpx` because it is plain secp256k1 point handling that
/// discv5's handshake needs too, and importing it from `rlpx` was the last thing tying
/// discovery to the wire protocol.
pub fn compress_pubkey(pk: H512) -> Option<PublicKey> {
    let mut full_pk = [0u8; 65];
    full_pk[0] = 0x04;
    full_pk[1..].copy_from_slice(&pk.0);
    PublicKey::from_slice(&full_pk).ok()
}
