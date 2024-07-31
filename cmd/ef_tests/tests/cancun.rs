use std::path::Path;

use ef_tests::test_runner::{execute_test, parse_test_file, validate_test};

fn parse_and_execute(path: &Path) -> datatest_stable::Result<()> {
    let tests = parse_test_file(path);

    for (test_key, test) in tests {
        validate_test(&test);
        execute_test(&test_key, &test)
    }
    Ok(())
}

#[allow(unused)]
fn parse_and_validate(path: &Path) -> datatest_stable::Result<()> {
    let tests = parse_test_file(path);

    for (_k, test) in tests {
        validate_test(&test);
    }
    Ok(())
}

//TODO: eip4844_blobs tests are not passing because they expect exceptions.
datatest_stable::harness!(
    parse_and_execute,
    "vectors/cancun/",
    r"eip1153_tstore/.*/.*\.json",
    // parse_and_execute,
    // "vectors/cancun/",
    // r"eip4788_beacon_root/.*/.*\.json",
    parse_and_execute,
    "vectors/cancun/",
    r"eip5656_mcopy/.*/.*\.json",
    // parse_and_execute,
    // "vectors/cancun/",
    // r"eip7516_blobgasfee/.*/.*\.json",
    // parse_and_execute,
    // "vectors/cancun/",
    // r"eip6780_selfdestruct/.*/.*\.json"
);

// datatest_stable::harness!(
//     parse_and_execute,
//     "vectors/cancun/",
//     r"eip4844_blobs/point_evaluation_precompile/valid_precompile_calls.json",
//     parse_and_execute,
//     "vectors/cancun/",
//     r"eip4788_beacon_root/beacon_root_contract/beacon_root_contract_calls.json",
//     parse_and_execute,
//     "vectors/cancun/",
//     r"eip5656_mcopy/mcopy_memory_expansion/mcopy_huge_memory_expansion.json",
//     parse_and_execute,
//     "vectors/cancun/",
//     r"eip4788_beacon_root/beacon_root_contract/invalid_beacon_root_calldata_value.json",
//     parse_and_validate,
//     "vectors/cancun/",
//     // we ignore `create_selfdestruct_same_tx.json` because it has some errors in the encoding
//     r"^(?!.*create_selfdestruct_same_tx.json)(.*.json)",
// );
