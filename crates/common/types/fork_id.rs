use std::fmt;

use crc32fast::Hasher;
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};

use ethereum_types::H32;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{BlockHash, BlockHeader, BlockNumber, ChainConfig};

// See https://github.com/ethereum/go-ethereum/blob/530adfc8e3ef9c8b6356facecdec10b30fb81d7d/core/forkid/forkid.go#L51
const TIMESTAMP_THRESHOLD: u64 = 1438269973;

#[derive(Clone, Debug, PartialEq, Default, Eq, Serialize, Deserialize)]
pub struct ForkId {
    pub fork_hash: H32,
    pub fork_next: BlockNumber,
}

impl fmt::Display for ForkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.fork_hash, self.fork_next)
    }
}

impl ForkId {
    pub fn new(
        chain_config: ChainConfig,
        genesis_header: BlockHeader,
        head_timestamp: u64,
        head_block_number: u64,
    ) -> Self {
        let genesis_hash = genesis_header.hash();
        let (block_number_based_forks, timestamp_based_forks) =
            chain_config.gather_forks(genesis_header);

        let mut fork_next;
        let mut hasher = Hasher::new();
        // Calculate the starting checksum from the genesis hash
        hasher.update(genesis_hash.as_bytes());

        // Update the checksum with the block number based forks
        fork_next = update_checksum(block_number_based_forks, &mut hasher, head_block_number);
        if fork_next > 0 {
            let fork_hash = H32::from_slice(&hasher.finalize().to_be_bytes());
            return Self {
                fork_hash,
                fork_next,
            };
        }
        // Update the checksum with the timestamp based forks
        fork_next = update_checksum(timestamp_based_forks, &mut hasher, head_timestamp);

        let fork_hash = hasher.finalize();
        let fork_hash = H32::from_slice(&fork_hash.to_be_bytes());
        Self {
            fork_hash,
            fork_next,
        }
    }

    // See https://eips.ethereum.org/EIPS/eip-2124#validation-rules.
    pub fn is_valid(
        &self,
        remote: Self,
        latest_block_number: u64,
        head_timestamp: u64,
        chain_config: ChainConfig,
        genesis_header: BlockHeader,
    ) -> bool {
        let genesis_hash = genesis_header.hash();
        let (block_number_based_forks, timestamp_based_forks) =
            chain_config.gather_forks(genesis_header);

        // Determine whether to compare the remote fork_next using a block number or a timestamp.
        let head = if head_timestamp >= TIMESTAMP_THRESHOLD {
            head_timestamp
        } else {
            latest_block_number
        };

        if remote.fork_hash == self.fork_hash {
            // validation rule #1
            if remote.fork_next <= head && remote.fork_next != 0 {
                debug!("Future fork already passed locally.");
                return false;
            }
            return true;
        }

        let forks = [block_number_based_forks, timestamp_based_forks].concat();
        let valid_combinations = get_all_fork_id_combinations(forks, genesis_hash);

        let mut is_subset = true;

        for (fork_hash, fork_next) in valid_combinations {
            if is_subset {
                // The remote hash is a subset of the local past forks (rule #2)
                if remote.fork_hash == fork_hash && remote.fork_next == fork_next {
                    return true;
                }
            } else {
                // The remote hash is a superset of the local past forks (rule #3)
                if remote.fork_hash == fork_hash {
                    return true;
                }
            }
            if fork_hash == self.fork_hash {
                // From this point on, if we have a match, it means the remote fork hash
                // is a superset of our local past forks.
                is_subset = false;
            }
        }
        // rule #4
        debug!("Local or remote needs software update.");
        false
    }
}

fn get_all_fork_id_combinations(forks: Vec<u64>, genesis_hash: BlockHash) -> Vec<(H32, u64)> {
    let mut combinations = vec![];
    let mut last_activation = 0;

    let mut hasher = Hasher::new();
    hasher.update(genesis_hash.as_bytes());
    for activation in forks {
        // If the block number or timestamp is already added, skip it.
        if activation == last_activation {
            continue;
        }
        combinations.push((
            H32::from_slice(&hasher.clone().finalize().to_be_bytes()),
            activation,
        ));
        hasher.update(&activation.to_be_bytes());
        last_activation = activation;
    }
    combinations.push((H32::from_slice(&hasher.finalize().to_be_bytes()), 0));
    combinations
}

fn update_checksum(forks: Vec<u64>, hasher: &mut Hasher, head: u64) -> u64 {
    let mut last_included = 0;

    for activation in forks {
        if activation <= head {
            if activation != last_included {
                hasher.update(&activation.to_be_bytes());
                last_included = activation;
            }
        } else {
            // fork_next found
            return activation;
        }
    }
    0
}

impl RLPEncode for ForkId {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf)
            .encode_field(&self.fork_hash)
            .encode_field(&self.fork_next)
            .finish();
    }
}

impl RLPDecode for ForkId {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (fork_hash, decoder) = decoder.decode_field("forkHash")?;
        let (fork_next, decoder) = decoder.decode_field("forkNext")?;
        let remaining = decoder.finish()?;
        let fork_id = ForkId {
            fork_hash,
            fork_next,
        };
        Ok((fork_id, remaining))
    }
}

#[cfg(test)]
mod tests {

    use std::{io::BufReader, str::FromStr};

    use hex_literal::hex;

    use crate::types::Genesis;

    use super::*;

    #[test]
    fn encode_fork_id() {
        let fork = ForkId {
            fork_hash: H32::zero(),
            fork_next: 0,
        };
        let expected = hex!("c6840000000080");
        assert_eq!(fork.encode_to_vec(), expected);
    }
    #[test]
    fn encode_fork_id2() {
        let fork = ForkId {
            fork_hash: H32::from_str("0xdeadbeef").unwrap(),
            fork_next: u64::from_str_radix("baddcafe", 16).unwrap(),
        };
        let expected = hex!("ca84deadbeef84baddcafe");
        assert_eq!(fork.encode_to_vec(), expected);
    }
    #[test]
    fn encode_fork_id3() {
        let fork = ForkId {
            fork_hash: H32::from_low_u64_le(u32::MAX.into()),
            fork_next: u64::MAX,
        };
        let expected = hex!("ce84ffffffff88ffffffffffffffff");
        assert_eq!(fork.encode_to_vec(), expected);
    }

    struct TestCase {
        head: u64,
        time: u64,
        fork_id: ForkId,
        is_valid: bool,
    }

    fn assert_test_cases(
        test_cases: Vec<TestCase>,
        chain_config: ChainConfig,
        genesis_header: BlockHeader,
    ) {
        for test_case in test_cases {
            let fork_id = ForkId::new(
                chain_config,
                genesis_header.clone(),
                test_case.time,
                test_case.head,
            );
            assert_eq!(
                fork_id.is_valid(
                    test_case.fork_id,
                    test_case.head,
                    test_case.time,
                    chain_config,
                    genesis_header.clone()
                ),
                test_case.is_valid
            )
        }
    }

    #[test]
    fn hoodi_test_cases() {
        let genesis_file = std::fs::File::open("../../cmd/ethrex/networks/hoodi/genesis.json")
            .expect("Failed to open genesis file");
        let genesis_reader = BufReader::new(genesis_file);
        let genesis: Genesis =
            serde_json::from_reader(genesis_reader).expect("Failed to read genesis file");
        let genesis_header = genesis.get_block().header;
        // See https://github.com/ethereum/go-ethereum/blob/444a6d007a08bddcec0b68b60ab507ea8bc1d078/core/forkid/forkid_test.go#L100
        let test_cases: Vec<TestCase> = vec![
            TestCase {
                head: 123,
                time: 0,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xbef71d30").unwrap(),
                    fork_next: 1742999832,
                },
                is_valid: true,
            },
            TestCase {
                head: 123,
                time: 1742999831,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xbef71d30").unwrap(),
                    fork_next: 1742999832,
                },
                is_valid: true,
            },
            TestCase {
                head: 123,
                time: 1742999832,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x0929e24e").unwrap(),
                    fork_next: 1761677592,
                },
                is_valid: true,
            },
            TestCase {
                head: 123,
                time: 1761677591,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x0929e24e").unwrap(),
                    fork_next: 1761677592,
                },
                is_valid: true,
            },
            TestCase {
                head: 123,
                time: 1761677592,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xe7e0e7ff").unwrap(),
                    fork_next: 1762365720,
                },
                is_valid: true,
            },
            TestCase {
                head: 123,
                time: 1762365719,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xe7e0e7ff").unwrap(),
                    fork_next: 1762365720,
                },
                is_valid: true,
            },
            TestCase {
                head: 123,
                time: 1762365720,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x3893353e").unwrap(),
                    fork_next: 1762955544,
                },
                is_valid: true,
            },
            TestCase {
                head: 123,
                time: 1762955543,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x3893353e").unwrap(),
                    fork_next: 1762955544,
                },
                is_valid: true,
            },
            TestCase {
                head: 123,
                time: 1762955544,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x23aa1351").unwrap(),
                    fork_next: 0,
                },
                is_valid: true,
            },
            TestCase {
                head: 123,
                time: 2740434112,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x23aa1351").unwrap(),
                    fork_next: 0,
                },
                is_valid: true,
            },
        ];
        assert_test_cases(test_cases, genesis.config, genesis_header);
    }

    fn get_sepolia_genesis() -> (Genesis, BlockHeader) {
        let genesis_file = std::fs::File::open("../../cmd/ethrex/networks/sepolia/genesis.json")
            .expect("Failed to open genesis file");
        let genesis_reader = BufReader::new(genesis_file);
        let genesis: Genesis =
            serde_json::from_reader(genesis_reader).expect("Failed to read genesis file");
        let genesis_header = genesis.get_block().header;
        (genesis, genesis_header)
    }
    #[test]
    fn sepolia_test_cases() {
        let (genesis, genesis_hash) = get_sepolia_genesis();
        // See https://github.com/ethereum/go-ethereum/blob/444a6d007a08bddcec0b68b60ab507ea8bc1d078/core/forkid/forkid_test.go#L83
        let test_cases: Vec<TestCase> = vec![
            TestCase {
                head: 0,
                time: 0,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xfe3366e7").unwrap(),
                    fork_next: 1735371,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735370,
                time: 0,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xfe3366e7").unwrap(),
                    fork_next: 1735371,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735371,
                time: 0,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xb96cbd13").unwrap(),
                    fork_next: 1677557088,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1677557087,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xb96cbd13").unwrap(),
                    fork_next: 1677557088,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1677557088,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xf7f9bc08").unwrap(),
                    fork_next: 1706655072,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1706655071,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xf7f9bc08").unwrap(),
                    fork_next: 1706655072,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1706655072,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x88cf81d9").unwrap(),
                    fork_next: 1741159776,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1741159775,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x88cf81d9").unwrap(),
                    fork_next: 1741159776,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1741159776,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xed88b5fd").unwrap(),
                    fork_next: 1760427360,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1760427359,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xed88b5fd").unwrap(),
                    fork_next: 1760427360,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1760427360,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xe2ae4999").unwrap(),
                    fork_next: 1761017184,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1761017183,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0xe2ae4999").unwrap(),
                    fork_next: 1761017184,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1761017184,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x56078a1e").unwrap(),
                    fork_next: 1761607008,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1761607007,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x56078a1e").unwrap(),
                    fork_next: 1761607008,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 1761607008,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x268956b6").unwrap(),
                    fork_next: 0,
                },
                is_valid: true,
            },
            TestCase {
                head: 1735372,
                time: 2741159776,
                fork_id: ForkId {
                    fork_hash: H32::from_str("0x268956b6").unwrap(),
                    fork_next: 0,
                },
                is_valid: true,
            },
        ];
        assert_test_cases(test_cases, genesis.config, genesis_hash);
    }

    #[test]
    fn remote_next_fork_passed_locally() {
        let local_head_block_number = 1000;
        let local_a = ForkId {
            fork_hash: H32::from_str("0x88cf81d9").unwrap(),
            fork_next: 0,
        };
        let local_b = ForkId {
            fork_hash: H32::from_str("0x88cf81d9").unwrap(),
            fork_next: 1500,
        };
        let remote = ForkId {
            fork_hash: H32::from_str("0x88cf81d9").unwrap(),
            fork_next: 100,
        };
        let result_a = local_a.is_valid(
            remote.clone(),
            local_head_block_number,
            0,
            ChainConfig::default(),
            BlockHeader::default(),
        );
        let result_b = local_b.is_valid(
            remote,
            local_head_block_number,
            0,
            ChainConfig::default(),
            BlockHeader::default(),
        );
        assert!(!result_a);
        assert!(!result_b);
    }

    #[test]
    fn local_needs_software_update() {
        let (genesis, genesis_hash) = get_sepolia_genesis();
        // in this case, we simply cannot build the fork_hash with all our valid combinations.
        let test_cases: Vec<TestCase> = vec![TestCase {
            head: 1735372,
            time: 2706655072,
            fork_id: ForkId {
                fork_hash: H32::random(),
                fork_next: 0,
            },
            is_valid: false,
        }];
        assert_test_cases(test_cases, genesis.config, genesis_hash);
    }

    #[test]
    fn remote_needs_software_update() {
        let (genesis, genesis_hash) = get_sepolia_genesis();
        // local is in Cancun fork.
        let local_time = 1706655072;
        // remote is in Shanghai fork and doesn't know about Cancun.
        let test_cases: Vec<TestCase> = vec![TestCase {
            head: 5443392,
            time: local_time,
            fork_id: ForkId {
                fork_hash: H32::from_str("0xf7f9bc08").unwrap(),
                fork_next: 0,
            },
            is_valid: false,
        }];
        assert_test_cases(test_cases, genesis.config, genesis_hash);
    }
}
