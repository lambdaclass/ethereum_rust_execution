use ethrex_common::{H160, types::ChainConfig};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::str::FromStr;

// Chain config for different forks as defined on https://ethereum.github.io/execution-spec-tests/v3.0.0/consuming_tests/common_types/#fork
lazy_static! {
    pub static ref MERGE_CONFIG: ChainConfig = ChainConfig {
        chain_id: 1_u64,
        homestead_block: Some(0),
        dao_fork_block: Some(0),
        dao_fork_support: true,
        eip150_block: Some(0),
        eip155_block: Some(0),
        eip158_block: Some(0),
        byzantium_block: Some(0),
        constantinople_block: Some(0),
        petersburg_block: Some(0),
        istanbul_block: Some(0),
        muir_glacier_block: Some(0),
        berlin_block: Some(0),
        london_block: Some(0),
        arrow_glacier_block: Some(0),
        gray_glacier_block: Some(0),
        merge_netsplit_block: Some(0),
        terminal_total_difficulty: Some(0),
        ..Default::default()
    };
    pub static ref MERGE_TO_SHANGHAI_AT_15K_CONFIG: ChainConfig = ChainConfig {
        shanghai_time: Some(0x3a98),
        ..*MERGE_CONFIG
    };
    pub static ref SHANGHAI_CONFIG: ChainConfig = ChainConfig {
        shanghai_time: Some(0),
        ..*MERGE_CONFIG
    };
    pub static ref SHANGHAI_TO_CANCUN_AT_15K_CONFIG: ChainConfig = ChainConfig {
        cancun_time: Some(0x3a98),
        ..*SHANGHAI_CONFIG
    };
    pub static ref CANCUN_CONFIG: ChainConfig = ChainConfig {
        cancun_time: Some(0),
        ..*SHANGHAI_CONFIG
    };
    pub static ref CANCUN_TO_PRAGUE_AT_15K_CONFIG: ChainConfig = ChainConfig {
        prague_time: Some(0x3a98),
        // Mainnet address
        deposit_contract_address: H160::from_str("0x00000000219ab540356cbb839cbe05303d7705fa")
            .unwrap(),
        ..*CANCUN_CONFIG
    };
    pub static ref PRAGUE_CONFIG: ChainConfig = ChainConfig {
        prague_time: Some(0),
        ..*CANCUN_TO_PRAGUE_AT_15K_CONFIG
    };

    pub static ref PRAGUE_TO_OSAKA_AT_15K_CONFIG: ChainConfig = ChainConfig {
        osaka_time: Some(0x3a98),
        ..*PRAGUE_CONFIG

    };

    pub static ref OSAKA_CONFIG: ChainConfig = ChainConfig {
        osaka_time: Some(0),
        ..*PRAGUE_CONFIG
    };

    pub static ref OSAKA_TO_BPO1_AT_15K_CONFIG: ChainConfig = ChainConfig {
        bpo1_time: Some(0x3a98),
        ..*OSAKA_CONFIG
    };

    pub static ref BPO1_TO_BPO2_AT_15K_CONFIG: ChainConfig = ChainConfig {
        bpo1_time: Some(0),
        bpo2_time: Some(0x3a98),
        ..*OSAKA_CONFIG
    };

    pub static ref BPO2_TO_BPO3_AT_15K_CONFIG: ChainConfig = ChainConfig {
        bpo2_time: Some(0),
        bpo3_time: Some(0x3a98),
        ..*OSAKA_CONFIG
    };
    pub static ref BPO3_TO_BPO4_AT_15K_CONFIG: ChainConfig = ChainConfig {
        bpo3_time: Some(0),
        bpo4_time: Some(0x3a98),
        ..*OSAKA_CONFIG
    };
    pub static ref BPO4_TO_BPO5_AT_15K_CONFIG: ChainConfig = ChainConfig {
        bpo4_time: Some(0),
        bpo5_time: Some(0x3a98),
        ..*OSAKA_CONFIG
    };

    pub static ref BPO2_CONFIG: ChainConfig = ChainConfig {
        bpo1_time: Some(0),
        bpo2_time: Some(0),
        ..*OSAKA_CONFIG
    };

    pub static ref BPO2_TO_AMSTERDAM_AT_15K_CONFIG: ChainConfig = ChainConfig {
        amsterdam_time: Some(0x3a98),
        ..*BPO2_CONFIG
    };

    pub static ref AMSTERDAM_CONFIG: ChainConfig = ChainConfig {
        amsterdam_time: Some(0),
        ..*BPO2_TO_AMSTERDAM_AT_15K_CONFIG
    };

    /// `Bogota` is the pseudo-fork the EIP-8141 fixtures are labelled with:
    /// Amsterdam plus frame transactions. EELS prototypes the EIP inside its
    /// Amsterdam module and fills with `--fork Bogota`; ethrex gates frame
    /// transactions on Hegota, which is the same fork under its ethrex name.
    pub static ref BOGOTA_CONFIG: ChainConfig = ChainConfig {
        hegota_time: Some(0),
        ..*AMSTERDAM_CONFIG
    };

}

/// Most of the fork variants are just for parsing the tests
/// It's important for the pre-merge forks to be before Paris because we make a comparison for executing post-merge forks only.
#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fork {
    Constantinople,
    #[serde(alias = "TangerineWhistle")]
    EIP150,
    #[serde(alias = "SpuriousDragon")]
    EIP158,
    EIP158ToByzantiumAt5,
    ArrowGlacierToParisAtDiffC0000,
    BerlinToLondonAt5,
    ByzantiumToConstantinopleFixAt5,
    FrontierToHomesteadAt5,
    HomesteadToDaoAt5,
    HomesteadToEIP150At5,
    Frontier,
    Homestead,
    ConstantinopleFix,
    Istanbul,
    Byzantium,
    London,
    Berlin,
    #[serde(alias = "Paris")]
    Merge,
    #[serde(alias = "ParisToShanghaiAtTime15k")]
    MergeToShanghaiAtTime15k,
    Shanghai,
    ShanghaiToCancunAtTime15k,
    Cancun,
    CancunToPragueAtTime15k,
    Prague,
    PragueToOsakaAtTime15k,
    Osaka,
    OsakaToBPO1AtTime15k,
    BPO1ToBPO2AtTime15k,
    BPO2ToBPO3AtTime15k,
    BPO3ToBPO4AtTime15k,
    BPO4ToBPO5AtTime15k,
    BPO2ToAmsterdamAtTime15k,
    Amsterdam,
    /// EELS's pseudo-fork for EIP-8141 fixtures: Amsterdam + frame transactions.
    /// Named `Hegota` inside ethrex.
    #[serde(alias = "Hegota")]
    Bogota,
}

impl Fork {
    pub fn chain_config(&self) -> &ChainConfig {
        match self {
            Fork::Merge => &MERGE_CONFIG,
            Fork::MergeToShanghaiAtTime15k => &MERGE_TO_SHANGHAI_AT_15K_CONFIG,
            Fork::Shanghai => &SHANGHAI_CONFIG,
            Fork::ShanghaiToCancunAtTime15k => &SHANGHAI_TO_CANCUN_AT_15K_CONFIG,
            Fork::Cancun => &CANCUN_CONFIG,
            Fork::CancunToPragueAtTime15k => &CANCUN_TO_PRAGUE_AT_15K_CONFIG,
            Fork::Prague => &PRAGUE_CONFIG,
            Fork::PragueToOsakaAtTime15k => &PRAGUE_TO_OSAKA_AT_15K_CONFIG,
            Fork::Osaka => &OSAKA_CONFIG,
            Fork::OsakaToBPO1AtTime15k => &OSAKA_TO_BPO1_AT_15K_CONFIG,
            Fork::BPO1ToBPO2AtTime15k => &BPO1_TO_BPO2_AT_15K_CONFIG,
            Fork::BPO2ToBPO3AtTime15k => &BPO2_TO_BPO3_AT_15K_CONFIG,
            Fork::BPO3ToBPO4AtTime15k => &BPO3_TO_BPO4_AT_15K_CONFIG,
            Fork::BPO4ToBPO5AtTime15k => &BPO4_TO_BPO5_AT_15K_CONFIG,
            Fork::BPO2ToAmsterdamAtTime15k => &BPO2_TO_AMSTERDAM_AT_15K_CONFIG,
            Fork::Amsterdam => &AMSTERDAM_CONFIG,
            Fork::Bogota => &BOGOTA_CONFIG,
            _ => {
                panic!("Ethrex doesn't support pre-Merge forks: {self:?}")
            }
        }
    }
}
