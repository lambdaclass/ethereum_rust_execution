# Ethrex Changelog

## Observability

### 2026-06-03

- Reduce allocations and clones [#6782](https://github.com/lambdaclass/ethrex/pull/6782)

### 2026-05-27

- Add BAL (EIP-7928) Prometheus instruments (`bal_blocks_total`, `bal_size_bytes`, `bal_size_bytes_histogram`, `bal_account_count`, `bal_slot_count`) and a BAL row in the `ethrex_l1_perf` Grafana dashboard [#6678](https://github.com/lambdaclass/ethrex/pull/6678)

## Perf

### 2026-09-03

- EIP-8037 (execution-specs#3478, consensus-breaking): when a successful child frame merges, the state-gas reservoir now repays the spill still outstanding in the merged frame back into `gas_remaining`, debiting the reservoir by the same amount. A cross-frame refund can credit the reservoir while the `gas_remaining` that funded the charge stays reduced; the merge is the first point where the claim and the credit share a frame. Billing-neutral by construction — the user total (`gas_limit - gas_remaining - reservoir`) and the EIP-7778 dimensions are unchanged — but it changes how much execution gas a parent frame has after a child returns, so it is consensus-visible. Fixtures move to `tests-glamsterdam-devnet@v8.1.4` [#7250](https://github.com/lambdaclass/ethrex/pull/7250)

### 2026-08-24

- Make `eth_estimateGas`'s plain-transfer short circuit fire. Its condition tested whether the recipient account existed rather than whether it had code, so every transfer to an ordinary funded wallet ran the full binary search instead of returning `TRANSACTION_GAS` at once [#7211](https://github.com/lambdaclass/ethrex/pull/7211)

### 2026-08-21

- Replace `RLPEncode::encode`'s `&mut dyn BufMut` sink with a concrete `&mut Vec<u8>`, removing a virtual call per encoded field, and write list payloads first so the length prefix is backpatched in place instead of pre-computed by a full `length()` re-encode. Together these drop the per-list scratch allocation `Encoder` used to make and the double traversal of every nested structure: `BlockHeader` -85%, `Receipt` -74%, `EIP1559Transaction` -73%, trie `Node::Leaf` -66%, `Node::Branch` -45% (-22% median across the RLP encode benchmarks) [#7180](https://github.com/lambdaclass/ethrex/pull/7180)

### 2026-08-03

- Size the default RocksDB shared block cache from the memory the process may actually use — 40% of the smaller of physical memory and the cgroup limit, clamped to 512 MiB..=12 GiB — instead of a flat 12 GiB. The flat default was 71% of a 16 GiB host, leaving no headroom for trie layers, execution and the mempool; `--rocksdb.block-cache-size` still overrides it. Detection reads `/proc`, so outside Linux the default stays at the 12 GiB ceiling; startup logs the detected limit and the resolved size
### 2026-07-29

- Breadth-first batched trie-node prefetch on the merkle storage-root path: one sorted RocksDB `multi_get` per trie level warms the touched nodes into the arena before the serial inserts, on the parallel BAL merkleizer (storage-root recomputation and the Stage C state-trie update) and the streaming (BAL-less / pre-Amsterdam) merkleizer. Warming-only, so the computed roots are byte-identical; large speedup on cold storage-heavy blocks [#6986](https://github.com/lambdaclass/ethrex/pull/6986)
### 2026-08-04

- Cut the cost of a cold contract-code access: store jump destinations as a 1-bit-per-byte bitmap instead of a persisted RLP list of `u32` offsets, count the bytecode in the code cache's byte budget, answer `EXTCODESIZE` from the code-length table instead of materializing the bytecode, and give the account-code column families a bloom filter (4KB data blocks on the blob-backed bytecode CF). Raises the code cache's byte budget from an effective 64 MiB of jump tables to 256 MiB of bytecode, and bumps the store schema version so an older binary warns rather than failing on the new value format. `COLD_ACCOUNT_CODE_ACCESS` drops from 7736 to 4652 gas in the EIP-8038 repricing fit, and `COLD_ACCOUNT_CODE_WRITE` from 10415 to 6355 [#7095](https://github.com/lambdaclass/ethrex/pull/7095)
- Batch and stream the BAL contract-code prefetch: warm accounts and their code in chunks instead of reading every access-list account before the first bytecode, take code hashes from the account read rather than a second lookup per account, and add a batched bytecode read that resolves the buffer and code cache first, then either fans out parallel point gets or shards the remainder across concurrent `multi_get`s, whichever reaches the greater read queue depth for the batch size on this host [#7099](https://github.com/lambdaclass/ethrex/pull/7099)

### 2026-08-07

- Access the EVM memory buffer without `RefCell`'s borrow-flag bookkeeping and round the `MLOAD`/`MSTORE` memory size once instead of twice [#7119](https://github.com/lambdaclass/ethrex/pull/7119)

### 2026-07-22

- Unify full-sync batch import onto the per-block execution pipeline, validating every block's state root and reusing the pipeline's BAL-driven parallel execution instead of the bespoke "execute all, apply once" batch path [#7008](https://github.com/lambdaclass/ethrex/pull/7008)

### 2026-07-16

- Prewarm each sender's ready transaction prefix so successor txs warm against their predecessors' state [#6999](https://github.com/lambdaclass/ethrex/pull/6999)

### 2026-07-08

- Batch BAL prefetch for storage-heavy blocks via sorted, sharded parallel rocksdb `multi_get` reads. The keys are sorted so adjacent entries share data blocks, then split into contiguous shards read concurrently, recovering the cold-read throughput a single serial `multi_get` loses (it runs at queue depth 1 since `async_io` is off). Applied to storage-slot prefetch (flat key-value table), account-state prefetch, and a complementary trie-node prefetch that warms the merkle node CFs concurrently with execution. Each path is gated on the count of missing (cold) slots/accounts (>= 16384, ~34M gas of cold reads), so warm and normal blocks keep the per-slot parallel point-gets while genuinely storage-heavy blocks take the sharded path, which also hardens against storage-bloat DoS [#6980](https://github.com/lambdaclass/ethrex/pull/6980)

### 2026-07-06

- Warm state caches between blocks by speculatively executing top-of-mempool transactions [#6967](https://github.com/lambdaclass/ethrex/pull/6967)

### 2026-07-01

- Precompute the `eth_getLogs` filter's address/topic blooms once instead of re-deriving them per block, removing redundant hashing from the header-bloom prefilter on wide-range queries [#6895](https://github.com/lambdaclass/ethrex/pull/6895)

### 2026-06-29

- Thread `Arc<BlockAccessList>` through the block pipeline to avoid an O(BAL-size) deep clone of the Block Access List (and its validation index) per block on the parallel execution path [#6829](https://github.com/lambdaclass/ethrex/pull/6829)

### 2026-06-19

- Parallelize single-account storage-trie merkleization: shard a hot account's (>=2048 slot updates) storage-root computation across 16 nibble-keyed workers, so one bloated contract no longer serializes its trie inserts on a single thread [#6845](https://github.com/lambdaclass/ethrex/pull/6845)

### 2026-06-18

- In-place top-slot mutation for unary/binary opcodes and `MLOAD`: mutate the top stack slot directly instead of pop-then-push, removing the serial read-modify-write of the stack offset on offset-chain-bound ops. ~2.16x on an ISZERO loop and ~1.63x on `MLOAD` (IPC 2.41 -> 3.45 on a 33M-op loop) [#6865](https://github.com/lambdaclass/ethrex/pull/6865)
- Monomorphize the LEVM opcode dispatch loop over whether a struct-log tracer is active (`run_dispatch::<const TRACED: bool>`), moving the per-opcode trace capture into cold out-of-line helpers. The non-traced path (the common case) drops the per-op tracer load/branches and the capture code's influence on loop codegen: ~36% fewer instructions and ~23% fewer cycles per opcode on a minimal op, lifting all-opcode dispatch throughput [#6847](https://github.com/lambdaclass/ethrex/pull/6847)
- Read a block's receipts in a single bulk read in `eth_getLogs` instead of a point lookup per transaction, ~5–7x faster on mainnet log queries [#6852](https://github.com/lambdaclass/ethrex/pull/6852)
- Skip non-matching blocks in `eth_getLogs` using the per-block header bloom, avoiding body/receipt loads for blocks that provably cannot match [#6813](https://github.com/lambdaclass/ethrex/pull/6813)

### 2026-06-15

- Pad `Code` bytecode with 33 trailing `STOP` bytes so the hot dispatch fetch and `pc` advance drop their bounds checks (~8% fewer instructions, ~13% fewer branches on dispatch). The logical length is tracked separately and `Code` is encapsulated so all consumers read the true length [#6866](https://github.com/lambdaclass/ethrex/pull/6866)

### 2026-06-10

- Route the native P256VERIFY (secp256r1, RIP-7212/EIP-7951) precompile through the `aws-lc-rs` (AWS-LC) backend, replacing the pure-Rust `p256` path on `NativeCrypto`; zkVM guest builds keep the portable backend [#6828](https://github.com/lambdaclass/ethrex/pull/6828)

### 2026-06-05

- Route the native BLS12-381 (EIP-2537) precompiles through the `blst` backend, replacing the pure-Rust path whose Fermat field inversion made `BLS12_G1ADD`/`BLS12_G2ADD` time-per-gas outliers; ~7.7x faster G1ADD, ~5.6x faster G2ADD (zkVM guest builds keep the portable backend) [#6792](https://github.com/lambdaclass/ethrex/pull/6792)

### 2026-06-03

- Short-circuit the `KECCAK256` opcode on zero-length input by returning the precomputed `keccak256("")` constant, skipping the permutation [#6775](https://github.com/lambdaclass/ethrex/pull/6775)

### 2026-05-28

- Batch account-state prefetch via rocksdb `multi_get_cf` on the flat key-value table [#6712](https://github.com/lambdaclass/ethrex/pull/6712)

### 2026-05-27

- Prefetch all BAL storage synchronously before execution [#6732](https://github.com/lambdaclass/ethrex/pull/6732)

### 2026-05-19

- Lazy BAL cursor for per-tx parallel execution [#6669](https://github.com/lambdaclass/ethrex/pull/6669)
- Move per-tx BAL validation into the rayon par_iter closure on the parallel execution path [#6677](https://github.com/lambdaclass/ethrex/pull/6677)

### 2026-05-18

- O(1) BAL recorder checkpoint via journal snapshots [#6667](https://github.com/lambdaclass/ethrex/pull/6667)

### 2026-05-15

- Replace synchronous disk I/O with async operations in snap sync [#6113](https://github.com/lambdaclass/ethrex/pull/6113)

### 2026-05-14

- Skip `vm.run_execution()` for transfers to codeless EOAs [#6570](https://github.com/lambdaclass/ethrex/pull/6570)
- BAL optimistic merkleization: synthesize state deltas from the input Block Access List pre-execution and merkleize in parallel with the EVM on the `engine_newPayload` validation path. Includes a parallel state-trie pre-warm and per-account hashed-key-sorted storage inserts to keep the trie node arena hot for Stage B/C [#6655](https://github.com/lambdaclass/ethrex/pull/6655)

### 2026-05-21

- Two-CF receipts migration: copy old RLP-keyed receipts to `receipts_v2` with fixed-width keys; old CF auto-dropped on restart [#6598](https://github.com/lambdaclass/ethrex/pull/6598)

### 2026-04-27

- Reduce peak disk usage during snap sync by moving SST files into the temp DB instead of copying [#6532](https://github.com/lambdaclass/ethrex/pull/6532)

### 2026-03-30

- Replace per-block thread spawning with persistent thread pool for merkleization [#6344](https://github.com/lambdaclass/ethrex/pull/6344)

### 2026-03-26

- Eliminate stack-frame spill in Stack::push for zero-upper-limb values [#6390](https://github.com/lambdaclass/ethrex/pull/6390)
- Use const-generic big-endian conversion in PUSH opcodes [#6390](https://github.com/lambdaclass/ethrex/pull/6390)

### 2026-03-05

- Doubly pipelined merkleization with self-coordinating shard workers [#6278](https://github.com/lambdaclass/ethrex/pull/6278)
- Switch hot EVM and mempool HashMaps to FxHashMap for faster hashing [#6303](https://github.com/lambdaclass/ethrex/pull/6303)

### 2026-03-02

- SIMD-accelerate trie nibble operations for block execution [#6286](https://github.com/lambdaclass/ethrex/pull/6286)
- Use FxHashMap in call frame backup [#6286](https://github.com/lambdaclass/ethrex/pull/6286)

### 2026-02-27

- Use nested storage originals, FxHashMap call frame backup, and sstore-specific storage access helper [#6265](https://github.com/lambdaclass/ethrex/pull/6265)
- Refactor LEVM opcode handlers to avoid expensive matches [#4791](https://github.com/lambdaclass/ethrex/pull/4791)

### 2026-02-25

- Speed up snap sync validation with parallelism and deduplication [#6191](https://github.com/lambdaclass/ethrex/pull/6191)
- Disable balance check for prewarming to avoid early reverts [#6259](https://github.com/lambdaclass/ethrex/pull/6259)

### 2026-02-24

- Expand fast-path dispatch in LEVM interpreter loop [#6245](https://github.com/lambdaclass/ethrex/pull/6245)

### 2026-02-23

- Check self before parent in Substate warm/cold lookups [#6244](https://github.com/lambdaclass/ethrex/pull/6244)
- Add precompile result cache shared between warmer and executor threads [#6243](https://github.com/lambdaclass/ethrex/pull/6243)

### 2026-02-13

- Optimize storage layer for block execution by reducing lock contention and allocations [#6207](https://github.com/lambdaclass/ethrex/pull/6207)

### 2026-02-06

- Defer KZG blob proof verification from P2P to mempool insertion [#6150](https://github.com/lambdaclass/ethrex/pull/6150)
- Cache ECDSA sender recovery in transaction structs [#6153](https://github.com/lambdaclass/ethrex/pull/6153)

### 2026-01-27

- Optimize prewarmer by grouping transactions by sender [#6047](https://github.com/lambdaclass/ethrex/pull/6047)
- Implement cache for `EXTCODESIZE` [#6034](https://github.com/lambdaclass/ethrex/pull/6034)

### 2026-01-23

- Compute base blob fee once per block [#6006](https://github.com/lambdaclass/ethrex/pull/6006)
- Reuse cache in prewarm workers [#5999](https://github.com/lambdaclass/ethrex/pull/5999)

### 2026-01-21

- Optimize `debug_executionWitness` by pre-serializing RPC format at storage time [#5956](https://github.com/lambdaclass/ethrex/pull/5956)
- Use fastbloom as the bloom filter [#5968](https://github.com/lambdaclass/ethrex/pull/5968)
- Improve snap sync logging with table format and visual progress bars [#5977](https://github.com/lambdaclass/ethrex/pull/5977)

### 2026-01-20

- Remove `ethrex-threadpool` crate and move `ThreadPool` to `ethrex-trie` [#5925](https://github.com/lambdaclass/ethrex/pull/5925)
- Add frame pointers setting to makefiles [#5746](https://github.com/lambdaclass/ethrex/pull/5746)
- Remove `Mutex<Box<_>>` from `DatabaseLogger::store` to reduce contention [#5930](https://github.com/lambdaclass/ethrex/pull/5930)

### 2026-01-19

- Use FxHashset for access lists [#5864](https://github.com/lambdaclass/ethrex/pull/5864)
- Prewarm cache by executing in parallel [#5906](https://github.com/lambdaclass/ethrex/pull/5906)

### 2026-01-15

- Reduce state iterated when calculating partial state transitions [#5864](https://github.com/lambdaclass/ethrex/pull/5864)

### 2026-01-13

- Remove needless allocs in CALLDATACOPY/CODECOPY/EXTCODECOPY [#5810](https://github.com/lambdaclass/ethrex/pull/5810)
- Inline common opcodes [#5761](https://github.com/lambdaclass/ethrex/pull/5761)
- Improve ecrecover precompile by removing heap allocs and conversions [#5709](https://github.com/lambdaclass/ethrex/pull/5709)

### 2026-01-12

- Refactor `ecpairing` using ark [#5792](https://github.com/lambdaclass/ethrex/pull/5792)

### 2025-12-23

- Remove needless allocs on store api [#5709](https://github.com/lambdaclass/ethrex/pull/5709)

### 2025-12-22

- Avoid double parsing and extra clones in doc signature formatting [#9285](https://github.com/starkware-libs/cairo/pull/9285)

### 2025-12-19

- Make HashSet use fxhash in discv4 peer_table [#5688](https://github.com/lambdaclass/ethrex/pull/5688)
- Validate tx blobs after checking if it's already in the mempool [#5686](https://github.com/lambdaclass/ethrex/pull/5686)

### 2025-12-15

- Parallelize storage merkelization [#6079](https://github.com/lambdaclass/ethrex/pull/6079)

### 2025-12-02

- Avoid unnecessary hashing of init codes and already hashed codes [#5397](https://github.com/lambdaclass/ethrex/pull/5397)

### 2025-11-28

- Change some calls from `encode_to_vec().len()` to `.length()` when wanting to get the rlp encoded length [#5374](https://github.com/lambdaclass/ethrex/pull/5374)
- Use our keccak implementation for receipts bloom filter calculation [#5454](https://github.com/lambdaclass/ethrex/pull/5454)

### 2025-11-27

- Use unchecked swap for stack [#5439](https://github.com/lambdaclass/ethrex/pull/5439)

### 2025-11-20

- Improve rlp encoding by avoiding extra loops and remove unneeded array vec, also adding a alloc-less length method the default trait impl [#5350](https://github.com/lambdaclass/ethrex/pull/5350)

### 2025-11-19

- Parallelize merkleization [#5377](https://github.com/lambdaclass/ethrex/pull/5377)

### 2025-11-17

- Avoid temporary allocations when decoding and hashing trie nodes [#5353](https://github.com/lambdaclass/ethrex/pull/5353)

### 2025-11-13

- Use specialized DUP implementation [#5324](https://github.com/lambdaclass/ethrex/pull/5324)
- Avoid recalculating blob base fee while preparing transactions [#5328](https://github.com/lambdaclass/ethrex/pull/5328)
- Use BlobDB for account_codes column family [#5300](https://github.com/lambdaclass/ethrex/pull/5300)

### 2025-11-12

- Only mark individual values as dirty instead of the whole trie [#5282](https://github.com/lambdaclass/ethrex/pull/5282)
- Separate Account and storage Column families in rocksdb [#5055](https://github.com/lambdaclass/ethrex/pull/5055)
- Avoid copying while reading account code [#5289](https://github.com/lambdaclass/ethrex/pull/5289)
- Cache `BLOBBASEFEE` opcode value [#5288](https://github.com/lambdaclass/ethrex/pull/5288)

### 2025-11-11

- Insert instead of merge for bloom rebuilds [#5223](https://github.com/lambdaclass/ethrex/pull/5223)
- Replace sha3 keccak to an assembly version using ffi [#5247](https://github.com/lambdaclass/ethrex/pull/5247)
- Fix `FlatKeyValue` generation on fullsync mode [#5274](https://github.com/lambdaclass/ethrex/pull/5274)

### 2025-11-10

- Disable RocksDB compression [#5223](https://github.com/lambdaclass/ethrex/pull/5223)

### 2025-11-07

- Reuse stack pool in LEVM [#5179](https://github.com/lambdaclass/ethrex/pull/5179)

### 2025-11-05

- Merkelization backpressure and batching [#5200](https://github.com/lambdaclass/ethrex/pull/5200)

### 2025-11-03

- Avoid unnecessary hash validations [#5167](https://github.com/lambdaclass/ethrex/pull/5167)
- Merge execution with some post-execution validations [#5170](https://github.com/lambdaclass/ethrex/pull/5170)

### 2025-10-31

- Reduce overhead of trie opening [#5145](https://github.com/lambdaclass/ethrex/pull/5145)
- Improved discovery and peer initialization [#5147](https://github.com/lambdaclass/ethrex/pull/5147)

### 2025-10-30

- Pipeline Merkleization and Execution [#5084](https://github.com/lambdaclass/ethrex/pull/5084)
- Add bloom filters to snapshot layers [#5112](https://github.com/lambdaclass/ethrex/pull/5112)
- Make trusted setup warmup non blocking [#5124](https://github.com/lambdaclass/ethrex/pull/5124)

### 2025-10-28

- Batch BlobsBundle::validate [#4993](https://github.com/lambdaclass/ethrex/pull/4993)
- Remove latest_block_header lock [#5050](https://github.com/lambdaclass/ethrex/pull/5050)

### 2025-10-27

- Run "engine_newPayload" block execution in a dedicated worker thread. [#5051](https://github.com/lambdaclass/ethrex/pull/5051)
- Reusing FindNode message per lookup loop instead of randomizing the key for each message. [#5047](https://github.com/lambdaclass/ethrex/pull/5047)

### 2025-10-23

- Move trie updates post block execution to a background thread. [#4989](https://github.com/lambdaclass/ethrex/pull/4989).

### 2025-10-21

- Instead of lazy computation of blocklist, do greedy computation of allowlist and store the result, fetch it with the DB. [#4961](https://github.com/lambdaclass/ethrex/pull/4961)

### 2025-10-20

- Remove duplicate subgroup check in ecpairing precompile [#4960](https://github.com/lambdaclass/ethrex/pull/4960)

### 2025-10-17

- Replaces incremental iteration with a one-time precompute method that scans the entire bytecode, building a `BitVec<u8, Msb0>` where bits mark valid `JUMPDEST` positions, skipping `PUSH1..PUSH32` data bytes.
- Updates `is_blacklisted` to O(1) bit lookup.

### 2025-10-14

- Improve get_closest_nodes p2p performance [#4838](https://github.com/lambdaclass/ethrex/pull/4838)

### 2025-10-13

- Remove explicit cache-related options from RocksDB configuration and reverted optimistic transactions to reduce RAM usage [#4853](https://github.com/lambdaclass/ethrex/pull/4853)
- Remove unnecesary mul in ecpairing [#4843](https://github.com/lambdaclass/ethrex/pull/4843)

### 2025-10-06

- Improve block headers vec handling in syncer [#4771](https://github.com/lambdaclass/ethrex/pull/4771)
- Refactor current_step sync metric from a `Mutex<String>` to a simple atomic. [#4772](https://github.com/lambdaclass/ethrex/pull/4772)

### 2025-10-01

- Change remaining_gas to i64, improving performance in gas cost calculations [#4684](https://github.com/lambdaclass/ethrex/pull/4684)

### 2025-09-30

- Downloading all slots of big accounts during the initial leaves download step of snap sync [#4689](https://github.com/lambdaclass/ethrex/pull/4689)
- Downloading and inserting intelligently accounts with the same state root and few (<= slots) [#4689](https://github.com/lambdaclass/ethrex/pull/4689)
- Improving the performance of state trie through an ordered insertion algorithm [#4689](https://github.com/lambdaclass/ethrex/pull/4689)

### 2025-09-29

- Remove `OpcodeResult` to improve tight loops of lightweight opcodes [#4650](https://github.com/lambdaclass/ethrex/pull/4650)

### 2025-09-24

- Avoid dumping empty storage accounts to disk [#4590](https://github.com/lambdaclass/ethrex/pull/4590)

### 2025-09-22

- Improve instruction fetching, dynamic opcode table based on configured fork, specialized push_zero in stack #[4579](https://github.com/lambdaclass/ethrex/pull/4579)

### 2025-09-17

- Refactor `bls12_g1add` to use `lambdaworks` [#4500](https://github.com/lambdaclass/ethrex/pull/4500)
- Refactor `bls12_g2add` to use `lambdaworks` [#4538](https://github.com/lambdaclass/ethrex/pull/4538)

### 2025-09-15

- Fix caching mechanism of the latest block's hash [#4479](https://github.com/lambdaclass/ethrex/pull/4479)
- Add `jemalloc` as an optional global allocator used by default [#4301](https://github.com/lambdaclass/ethrex/pull/4301)

- Improve time when downloading bytecodes from peers [#4487](https://github.com/lambdaclass/ethrex/pull/4487)

### 2025-09-11

- Add `RocksDB` as an optional storage engine [#4272](https://github.com/lambdaclass/ethrex/pull/4272)

### 2025-09-10

- Implement fast partition of `TrieIterator` and use it for quickly responding `GetAccountRanges` and `GetStorageRanges` [#4404](https://github.com/lambdaclass/ethrex/pull/4404)

### 2025-09-09

- Refactor substrate backup mechanism to avoid expensive clones [#4381](https://github.com/lambdaclass/ethrex/pull/4381)

### 2025-09-02

- Use x86-64-v2 cpu target on linux by default, dockerfile will use it too. [#4252](https://github.com/lambdaclass/ethrex/pull/4252)

### 2025-09-01

- Process JUMPDEST gas and pc together with the given JUMP JUMPI opcode, improving performance. #[4220](https://github.com/lambdaclass/ethrex/pull/4220)

### 2025-08-29

- Improve P2P mempool gossip performance [#4205](https://github.com/lambdaclass/ethrex/pull/4205)

### 2025-08-28

- Improve precompiles further: modexp, ecrecover [#4168](https://github.com/lambdaclass/ethrex/pull/4168)

### 2025-08-27

- Improve memory resize performance [#4117](https://github.com/lambdaclass/ethrex/pull/4177)

### 2025-08-25

- Improve calldatacopy opcode further [#4150](https://github.com/lambdaclass/ethrex/pull/4150)

### 2025-08-22

- Improve Memory::load_range by returning a Bytes directly, avoding a vec allocation [#4098](https://github.com/lambdaclass/ethrex/pull/4098)

- Improve ecpairing (bn128) precompile [#4130](https://github.com/lambdaclass/ethrex/pull/4130)

### 2025-08-20

- Improve BLS12 precompile [#4073](https://github.com/lambdaclass/ethrex/pull/4073)

- Improve blobbasefee opcode [#4092](https://github.com/lambdaclass/ethrex/pull/4092)

- Make precompiles use a constant table [#4097](https://github.com/lambdaclass/ethrex/pull/4097)

### 2025-08-19

- Improve addmod and mulmod opcode performance [#4072](https://github.com/lambdaclass/ethrex/pull/4072)

- Improve signextend opcode performance [#4071](https://github.com/lambdaclass/ethrex/pull/4071)

- Improve performance of calldataload, calldatacopy, extcodecopy, codecopy, returndatacopy [#4070](https://github.com/lambdaclass/ethrex/pull/4070)

### 2025-08-14

- Use malachite crate to handle big integers in modexp, improving perfomance [#4045](https://github.com/lambdaclass/ethrex/pull/4045)

### 2025-07-31

- Cache chain config and latest canonical block header [#3878](https://github.com/lambdaclass/ethrex/pull/3878)

- Batching of transaction hashes sent in a single NewPooledTransactionHashes message [#3912](https://github.com/lambdaclass/ethrex/pull/3912)

- Make `JUMPDEST` blacklist lazily generated on-demand [#3812](https://github.com/lambdaclass/ethrex/pull/3812)
- Rewrite Blake2 AVX2 implementation (avoid gather instructions and better loop handling).
- Add Blake2 NEON implementation.

### 2025-07-30

- Add a secondary index keyed by sender+nonce to the mempool to avoid linear lookups [#3865](https://github.com/lambdaclass/ethrex/pull/3865)

### 2025-07-24

- Refactor current callframe to avoid handling avoidable errors, improving performance [#3816](https://github.com/lambdaclass/ethrex/pull/3816)

- Add shortcut to avoid callframe creation on precompile invocations [#3802](https://github.com/lambdaclass/ethrex/pull/3802)

### 2025-07-21

- Use `rayon` to recover the sender address from transactions [#3709](https://github.com/lambdaclass/ethrex/pull/3709)

### 2025-07-18

- Migrate EcAdd and EcMul to Arkworks [#3719](https://github.com/lambdaclass/ethrex/pull/3719)

- Add specialized push1 and pop1 to stack [#3705](https://github.com/lambdaclass/ethrex/pull/3705)

- Improve precompiles by avoiding 0 value transfers [#3715](https://github.com/lambdaclass/ethrex/pull/3715)

- Improve BlobHash [#3704](https://github.com/lambdaclass/ethrex/pull/3704)

  Added push1 and pop1 to avoid using arrays for single variable operations.

  Avoid checking for blob hashes length twice.

### 2025-07-17

- Use a lookup table for opcode execution [#3669](https://github.com/lambdaclass/ethrex/pull/3669)

- Improve CodeCopy perfomance [#3675](https://github.com/lambdaclass/ethrex/pull/3675)

- Improve sstore perfomance further [#3657](https://github.com/lambdaclass/ethrex/pull/3657)

### 2025-07-16

- Improve levm memory model [#3564](https://github.com/lambdaclass/ethrex/pull/3564)

### 2025-07-15

- Add sstore bench [#3552](https://github.com/lambdaclass/ethrex/pull/3552)

### 2025-07-10

- Add AVX256 implementation of BLAKE2 [#3590](https://github.com/lambdaclass/ethrex/pull/3590)

### 2025-07-08

- Improve sstore opcodes [#3555](https://github.com/lambdaclass/ethrex/pull/3555)

### 2025-07-07

- Improve blake2f [#3503](https://github.com/lambdaclass/ethrex/pull/3503)

### 2025-06-30

- Use a stack pool [#3386](https://github.com/lambdaclass/ethrex/pull/3386)

### 2025-06-27

- Reduce handle_debug runtime cost [#3356](https://github.com/lambdaclass/ethrex/pull/3356)
- Improve U256 decoding and PUSHX [#3332](https://github.com/lambdaclass/ethrex/pull/3332)

### 2025-06-26

- Refactor jump opcodes to use a blacklist on invalid targets.

### 2025-06-20

- Use a lookup table for opcode parsing [#3253](https://github.com/lambdaclass/ethrex/pull/3253)
- Use specialized PUSH1 and PUSH2 implementations [#3262](https://github.com/lambdaclass/ethrex/pull/3262)

### 2025-05-27

- Improved the performance of shift instructions. [2933](https://github.com/lambdaclass/ethrex/pull/2933)

- Refactor Patricia Merkle Trie to avoid rehashing the entire path on every insert [2687](https://github.com/lambdaclass/ethrex/pull/2687)

### 2025-05-22

- Add immutable cache to LEVM that stores in memory data read from the Database so that getting account doesn't need to consult the Database again. [2829](https://github.com/lambdaclass/ethrex/pull/2829)

### 2025-05-20

- Reduce account clone overhead when account data is retrieved [2684](https://github.com/lambdaclass/ethrex/pull/2684)

### 2025-04-30

- Reduce transaction clone and Vec grow overhead in mempool [2637](https://github.com/lambdaclass/ethrex/pull/2637)

### 2025-04-28

- Make TrieDb trait use NodeHash as key [2517](https://github.com/lambdaclass/ethrex/pull/2517)

### 2025-04-22

- Avoid calculating state transitions after every block in bulk mode [2519](https://github.com/lambdaclass/ethrex/pull/2519)

- Transform the inlined variant of NodeHash to a constant sized array [2516](https://github.com/lambdaclass/ethrex/pull/2516)

### 2025-04-11

- Removed some unnecessary clones and made some functions const: [2438](https://github.com/lambdaclass/ethrex/pull/2438)

- Asyncify some DB read APIs, as well as its users [#2430](https://github.com/lambdaclass/ethrex/pull/2430)

### 2025-04-09

- Fix an issue where the table was locked for up to 20 sec when performing a ping: [2368](https://github.com/lambdaclass/ethrex/pull/2368)

#### 2025-04-03

- Fix a bug where RLP encoding was being done twice: [#2353](https://github.com/lambdaclass/ethrex/pull/2353), check
  the report under `docs/perf_reports` for more information.

#### 2025-04-01

- Asyncify DB write APIs, as well as its users [#2336](https://github.com/lambdaclass/ethrex/pull/2336)

#### 2025-03-30

- Faster block import, use a slice instead of copy
  [#2097](https://github.com/lambdaclass/ethrex/pull/2097)

#### 2025-02-28

- Don't recompute transaction senders when building blocks [#2097](https://github.com/lambdaclass/ethrex/pull/2097)

#### 2025-03-21

- Process blocks in batches when syncing and importing [#2174](https://github.com/lambdaclass/ethrex/pull/2174)

### 2025-03-27

- Compute tx senders in parallel [#2268](https://github.com/lambdaclass/ethrex/pull/2268)
