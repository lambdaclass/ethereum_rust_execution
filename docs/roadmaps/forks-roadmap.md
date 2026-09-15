# Forks Team Roadmap - ethrex

Next fork: **Glamsterdam** (CL Gloas, EL Amsterdam). Mainnet date not yet scheduled.

| Acronym | Meaning |
|---------|---------|
| **SFI** | Scheduled for Inclusion - will be in the fork |
| **CFI** | Considered for Inclusion - likely, under discussion |
| **PFI** | Proposed for Inclusion - proposed |
| **DFI** | Declined for Inclusion - won't be included |
| **BAL** | Block-Level Access Lists (EIP-7928) |

---

## Current Devnet

**glamsterdam-devnet-8**

- Spec baseline: [`devnets/glamsterdam/8`](https://github.com/ethereum/execution-specs/tree/devnets/glamsterdam/8)
- Fixtures: [`tests-glamsterdam-devnet@v8.1.1`](https://github.com/ethereum/execution-specs/releases/tag/tests-glamsterdam-devnet@v8.1.1)
- EELS commit: `32f597f7e56e3843198a83c7cf437a0b49aa6c0e` (the v8.1.1 tag, also the tip of `devnets/glamsterdam/8`)
- Status: 🟢 aligned — blockchain, state and engine ef-tests green on the v8.1.1 bundle
- Tracking: [#6583]

**Bumping to a new bundle:** edit `tooling/ef_tests/.fixtures_url_amsterdam` and
`.github/config/hive/amsterdam.yaml` (`fixtures` + `eels_commit`) — both, always, since
grading one release's client against another's bundle fails every fixture the releases
disagree on — then re-run the three ef-test suites and hive `eels/consume-engine`
Amsterdam. Upstream expects at least two follow-up releases on this devnet; v8.1.0 and
v8.1.1 have shipped, carrying coverage rather than new semantics.

v8.1.1 was announced as coverage-only, which holds for the numbers: the amsterdam fork
diff is a `Uint` -> `ExecutionGas` type-wrapper refactor with every value unchanged. One
behaviour did change — `calculate_excess_blob_gas` now reads the blob fields from a
`PreviousHeader` as well as a `Header` ([specs#3352]), so accumulated excess blob gas
survives a fork transition instead of resetting to zero at the fork block. ethrex already
matched, since `calc_excess_blob_gas` reads the parent unconditionally.

## Next up

| Item | Why it matters |
|------|----------------|
| **EIP-8070 (eth/72)** | Mandatory for all ELs on devnet-8. In review at [#6776]. Ships no fixtures and hive covers it execute-only ([hive#1365]), so the bundle gives it zero coverage either way — needs an `execute` sim wired up. |
| **`debug_getRawBlockAccessList`** | Protocol-side requirement per [execution-apis#851](https://github.com/ethereum/execution-apis/pull/851) (merged), along with `-32001`/`4444` for the BAL getters. Implemented by [#7069]. |
| **EIP-8038 spec text** | The v8.0.0 access-list repricing landed in the tests ahead of its EIPs PR. Confirm the EIP matches once that merges. |
| **`eth_simulateV1`** | Implemented ([#6212]): multi-block simulation with state/block overrides, `validation`, `traceTransfers` and `returnFullTransactions`, spec error codes (-38010..-38026). Engine in `crates/blockchain/simulate.rs`, handler in `crates/networking/rpc/eth/simulate.rs`. Known gaps, documented in the engine: Amsterdam EIP-8037 2D gas / EIP-7928 BAL headers are not modeled, `maxUsedGas` reports pre-refund gas rather than geth's in-flight peak, and `movePrecompileToAddress` is validated but not applied (the engine builds its EVM with `new_evm`, so it never installs the relocations that `Blockchain::new_overlaid_evm` sets up for the `eth_call` family). The hive `rpc-compat` pin predates the `eth_simulateV1` test corpus, so CI does not exercise it yet; conformance is covered by ported `.io` scenarios in the RPC crate's tests. |
| **EIP-8189 (snap/2)** | BAL-based state healing, newly listed in [EIP-7773]. Not evaluated. |
| **EIP-7904** | Informational compute-gas analysis; only a Nethermind draft ([#9619]) exists. Revisit if it reaches SFI. |

---

## Implementation Status

### Amsterdam EL — devnet-8 scope (16 EIPs per [EIP-7773])

15 implemented, EIP-8070 in review. The gas EIPs repriced in v8.0.0:

| EIP | Title | devnet-8 pricing | Owner |
|-----|-------|------------------|-------|
| **2780** | Resource-based Intrinsic Transaction Gas | transfer log cost folded into a flat `TX_VALUE_COST` of 6000; a creation carrying value pays no value charge | Edgar |
| **8038** | State-Access Gas Cost Update | access-list entries cost the cold access minus `WARM_ACCESS` (2900), so prepaying is gas neutral | Edgar |
| **8037** | State Creation Gas Cost (2D gas) | flat two-dimensional inclusion gate; only the execution dimension is capped at `TX_MAX_GAS_LIMIT` | Edgar |
| **7928** | Block-Level Access Lists | unchanged in v8.0.0 | Edgar |

Also implemented and passing: **7708** ETH transfers emit logs (Edgar), **7778** block gas
accounting without refunds (Edgar), **7843** SLOTNUM (Esteve), **8024**
DUPN/SWAPN/EXCHANGE (Esteve), **7976** calldata floor cost, **7981** access list cost,
**7954** max contract size (24→32 KiB), **7610** revert creation on non-empty storage,
**8246** remove SELFDESTRUCT burn, **8282** builder execution requests, **7997**
deterministic factory (genesis predeploy, no client code).

Outside the devnet-8 set: **8159** eth/71 BAL exchange, **7975** eth/70 partial receipt
lists, **7872** max blob flag (PFI), **8025** optional execution proofs ([#6361], #6516,
#6549, #6560 — Hegotá PFI per [EIP-8081], may end up Hegotá-only).

### Not implemented — EL candidates

| EIP | Title | Stage |
|-----|-------|-------|
| **7904** | Compute Gas Cost Analysis | CFI (Informational) |
| **7979** | Call/Return Opcodes | PFI |
| **8163** | Reserve Opcode | PFI |
| **8189** | snap/2 BAL-Based State Healing | listed in [EIP-7773], not evaluated |

### CL-side

No EL work; tracked so ACDE outcomes are visible. **7732** ePBS (SFI, CL headliner),
**7688** forward-compatible consensus structures, **8045** exclude slashed validators from
proposing, **8061** exit/consolidation churn, **8080** exits via the consolidation queue,
**8136** cell-level deltas for data column broadcast.

Glamsterdam declined 47 EIPs per [EIP-7773], including EIP-7692 (EOF) and EIP-7937
(64-bit EVM). EIP-7805 (FOCIL) was re-targeted at Hegotá.

### Would reopen if re-proposed

- **Deferred-on-success state-gas charging** for `CREATE`/`CREATE2`/`CALL*` — misilva73
  audit point #3 in [specs#2804](https://github.com/ethereum/execution-specs/issues/2804),
  declined for the BAL devnets.
- **Debug receipt fields** — extending `debug_getBlockReceipts` with `regularGasUsed` /
  `stateGasCharged` / `stateGasRefunded` / `cumulative*`
  ([PM #2033](https://github.com/ethereum/pm/issues/2033#issuecomment-4397074196)). A
  cross-client debug aid, not fork scope.

---

## Fork Infrastructure

The fork enum lives in `crates/common/types/genesis.rs`, ending at `Amsterdam`;
activation timestamps are `ChainConfig` fields, with `bpo1_time`..`bpo5_time` already
defined for the BPOs and Hegotá. Amsterdam timestamps are wired into the holesky, sepolia
and hoodi genesis files under `cmd/ethrex/networks/`.

---

## Next Fork: Hegotá (H2 2026)

CL = **Heka**, EL = **Bogotá**; primary source [EIP-8081].

- **SFI:** **7805** FOCIL — headliner, promoted after being declined from Glamsterdam.
- **CFI:** **8141** Frame Transaction (account abstraction) — lost the headliner debate,
  retained as a non-headliner.
- **PFI:** **4758** deactivate `SELFDESTRUCT`, **7709** read `BLOCKHASH` from storage,
  **7716** anti-correlation attestation penalties, **8025** optional execution proofs,
  **8188** state tiering by write age, **8205** withdrawal credentials preregistration,
  **8253** bump nonce of zero-nonce storage accounts.

---

## Meetings

- **ACDE** — Thursdays. Attend live, or review the recording and transcript afterwards for
  CFI/SFI status changes.
- **ACDT** (testing) — Mondays, followed by Edgar.

Agendas and notes for both: [ethereum/pm](https://github.com/ethereum/pm).

## Links

- [EIP-7773 Meta Glamsterdam][EIP-7773] · [EIP-8081 Meta Hegotá][EIP-8081]
- [Upstream tracker — execution-specs#2804](https://github.com/ethereum/execution-specs/issues/2804)
- [Reth Amsterdam tracking issue](https://github.com/paradigmxyz/reth/issues/18783)
- [ethrex docs/eip.md](../eip.md) — EIP tracking
- [ethrex ROADMAP.md](../../ROADMAP.md) — general roadmap

[#9619]: https://github.com/NethermindEth/nethermind/pull/9619
[hive#1365]: https://github.com/ethereum/hive/pull/1365
[specs#3352]: https://github.com/ethereum/execution-specs/pull/3352
[#6212]: https://github.com/lambdaclass/ethrex/issues/6212
[#6361]: https://github.com/lambdaclass/ethrex/pull/6361
[#6583]: https://github.com/lambdaclass/ethrex/issues/6583
[#6776]: https://github.com/lambdaclass/ethrex/pull/6776
[#7069]: https://github.com/lambdaclass/ethrex/pull/7069
[EIP-7773]: https://eips.ethereum.org/EIPS/eip-7773
[EIP-8081]: https://eips.ethereum.org/EIPS/eip-8081
