use crate::{
    errors::{OpcodeResult, VMError},
    opcode_handlers::{
        OpInvalidHandler, OpStopHandler, OpcodeHandler, arithmetic::*, bitwise_comparison::*,
        block::*, dup::*, environment::*, exchange::*, frame_tx::*, keccak::*, logging::*, push::*,
        stack_memory_storage_flow::*, system::*,
    },
    vm::VM,
};
use ethrex_common::types::Fork;
use std::cell::OnceCell;
use strum::EnumString;

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, EnumString, Hash)]
pub enum Opcode {
    // Stop and Arithmetic Operations
    STOP = 0x00,
    ADD = 0x01,
    MUL = 0x02,
    SUB = 0x03,
    DIV = 0x04,
    SDIV = 0x05,
    MOD = 0x06,
    SMOD = 0x07,
    ADDMOD = 0x08,
    MULMOD = 0x09,
    EXP = 0x0A,
    SIGNEXTEND = 0x0B,

    // Comparison & Bitwise Logic Operations
    LT = 0x10,
    GT = 0x11,
    SLT = 0x12,
    SGT = 0x13,
    EQ = 0x14,
    ISZERO = 0x15,
    AND = 0x16,
    OR = 0x17,
    XOR = 0x18,
    NOT = 0x19,
    BYTE = 0x1A,
    SHL = 0x1B,
    SHR = 0x1C,
    SAR = 0x1D,
    CLZ = 0x1E,

    // KECCAK256
    KECCAK256 = 0x20,

    // Environmental Information
    ADDRESS = 0x30,
    BALANCE = 0x31,
    ORIGIN = 0x32,
    CALLER = 0x33,
    CALLVALUE = 0x34,
    CALLDATALOAD = 0x35,
    CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37,
    CODESIZE = 0x38,
    CODECOPY = 0x39,
    GASPRICE = 0x3A,
    EXTCODESIZE = 0x3B,
    EXTCODECOPY = 0x3C,
    RETURNDATASIZE = 0x3D,
    RETURNDATACOPY = 0x3E,
    EXTCODEHASH = 0x3F,

    // Block Information
    BLOCKHASH = 0x40,
    COINBASE = 0x41,
    TIMESTAMP = 0x42,
    NUMBER = 0x43,
    PREVRANDAO = 0x44,
    GASLIMIT = 0x45,
    CHAINID = 0x46,
    SELFBALANCE = 0x47,
    BASEFEE = 0x48,
    BLOBHASH = 0x49,
    BLOBBASEFEE = 0x4A,
    SLOTNUM = 0x4B,

    // Stack, Memory, Storage, and Flow Operations
    POP = 0x50,
    MLOAD = 0x51,
    MSTORE = 0x52,
    MSTORE8 = 0x53,
    SLOAD = 0x54,
    SSTORE = 0x55,
    JUMP = 0x56,
    JUMPI = 0x57,
    PC = 0x58,
    MSIZE = 0x59,
    GAS = 0x5A,
    JUMPDEST = 0x5B,
    TLOAD = 0x5C,
    TSTORE = 0x5D,
    MCOPY = 0x5E,

    // Push Operations
    PUSH0 = 0x5F,
    PUSH1 = 0x60,
    PUSH2 = 0x61,
    PUSH3 = 0x62,
    PUSH4 = 0x63,
    PUSH5 = 0x64,
    PUSH6 = 0x65,
    PUSH7 = 0x66,
    PUSH8 = 0x67,
    PUSH9 = 0x68,
    PUSH10 = 0x69,
    PUSH11 = 0x6A,
    PUSH12 = 0x6B,
    PUSH13 = 0x6C,
    PUSH14 = 0x6D,
    PUSH15 = 0x6E,
    PUSH16 = 0x6F,
    PUSH17 = 0x70,
    PUSH18 = 0x71,
    PUSH19 = 0x72,
    PUSH20 = 0x73,
    PUSH21 = 0x74,
    PUSH22 = 0x75,
    PUSH23 = 0x76,
    PUSH24 = 0x77,
    PUSH25 = 0x78,
    PUSH26 = 0x79,
    PUSH27 = 0x7A,
    PUSH28 = 0x7B,
    PUSH29 = 0x7C,
    PUSH30 = 0x7D,
    PUSH31 = 0x7E,
    PUSH32 = 0x7F,

    // Duplication Operations
    DUP1 = 0x80,
    DUP2 = 0x81,
    DUP3 = 0x82,
    DUP4 = 0x83,
    DUP5 = 0x84,
    DUP6 = 0x85,
    DUP7 = 0x86,
    DUP8 = 0x87,
    DUP9 = 0x88,
    DUP10 = 0x89,
    DUP11 = 0x8A,
    DUP12 = 0x8B,
    DUP13 = 0x8C,
    DUP14 = 0x8D,
    DUP15 = 0x8E,
    DUP16 = 0x8F,

    // Swap Operations
    SWAP1 = 0x90,
    SWAP2 = 0x91,
    SWAP3 = 0x92,
    SWAP4 = 0x93,
    SWAP5 = 0x94,
    SWAP6 = 0x95,
    SWAP7 = 0x96,
    SWAP8 = 0x97,
    SWAP9 = 0x98,
    SWAP10 = 0x99,
    SWAP11 = 0x9A,
    SWAP12 = 0x9B,
    SWAP13 = 0x9C,
    SWAP14 = 0x9D,
    SWAP15 = 0x9E,
    SWAP16 = 0x9F,
    // Logging Operations
    LOG0 = 0xA0,
    LOG1 = 0xA1,
    LOG2 = 0xA2,
    LOG3 = 0xA3,
    LOG4 = 0xA4,
    // EIP-8141 Frame Transaction opcodes
    APPROVE = 0xAA,
    TXPARAM = 0xB0,
    FRAMEDATALOAD = 0xB1,
    FRAMEDATACOPY = 0xB2,
    FRAMEPARAM = 0xB3,
    SIGPARAM = 0xB4,
    SIGDATACOPY = 0xB5,
    // EIP-8024
    DUPN = 0xE6,
    SWAPN = 0xE7,
    EXCHANGE = 0xE8,
    // System Operations
    CREATE = 0xF0,
    CALL = 0xF1,
    CALLCODE = 0xF2,
    RETURN = 0xF3,
    DELEGATECALL = 0xF4,
    CREATE2 = 0xF5,
    STATICCALL = 0xFA,
    REVERT = 0xFD,
    INVALID = 0xFE,
    SELFDESTRUCT = 0xFF,
}

impl From<u8> for Opcode {
    #[expect(clippy::as_conversions)]
    fn from(byte: u8) -> Self {
        // We use a manual lookup table instead of a match because it gives improved perfomance
        // See https://godbolt.org/z/eG8M1jz3M
        const OPCODE_TABLE: [Opcode; 256] = const {
            let mut table = [Opcode::INVALID; 256];
            table[0x00] = Opcode::STOP;
            table[0x01] = Opcode::ADD;
            table[0x16] = Opcode::AND;
            table[0x17] = Opcode::OR;
            table[0x18] = Opcode::XOR;
            table[0x19] = Opcode::NOT;
            table[0x1A] = Opcode::BYTE;
            table[0x1B] = Opcode::SHL;
            table[0x1C] = Opcode::SHR;
            table[0x1D] = Opcode::SAR;
            table[0x1E] = Opcode::CLZ;
            table[0x02] = Opcode::MUL;
            table[0x03] = Opcode::SUB;
            table[0x04] = Opcode::DIV;
            table[0x05] = Opcode::SDIV;
            table[0x06] = Opcode::MOD;
            table[0x07] = Opcode::SMOD;
            table[0x08] = Opcode::ADDMOD;
            table[0x09] = Opcode::MULMOD;
            table[0x0A] = Opcode::EXP;
            table[0x0B] = Opcode::SIGNEXTEND;
            table[0x10] = Opcode::LT;
            table[0x11] = Opcode::GT;
            table[0x12] = Opcode::SLT;
            table[0x13] = Opcode::SGT;
            table[0x14] = Opcode::EQ;
            table[0x15] = Opcode::ISZERO;
            table[0x20] = Opcode::KECCAK256;
            table[0x30] = Opcode::ADDRESS;
            table[0x31] = Opcode::BALANCE;
            table[0x32] = Opcode::ORIGIN;
            table[0x33] = Opcode::CALLER;
            table[0x34] = Opcode::CALLVALUE;
            table[0x35] = Opcode::CALLDATALOAD;
            table[0x36] = Opcode::CALLDATASIZE;
            table[0x37] = Opcode::CALLDATACOPY;
            table[0x38] = Opcode::CODESIZE;
            table[0x39] = Opcode::CODECOPY;
            table[0x3A] = Opcode::GASPRICE;
            table[0x3B] = Opcode::EXTCODESIZE;
            table[0x3C] = Opcode::EXTCODECOPY;
            table[0x3D] = Opcode::RETURNDATASIZE;
            table[0x3E] = Opcode::RETURNDATACOPY;
            table[0x3F] = Opcode::EXTCODEHASH;
            table[0x40] = Opcode::BLOCKHASH;
            table[0x41] = Opcode::COINBASE;
            table[0x42] = Opcode::TIMESTAMP;
            table[0x43] = Opcode::NUMBER;
            table[0x44] = Opcode::PREVRANDAO;
            table[0x45] = Opcode::GASLIMIT;
            table[0x46] = Opcode::CHAINID;
            table[0x47] = Opcode::SELFBALANCE;
            table[0x48] = Opcode::BASEFEE;
            table[0x49] = Opcode::BLOBHASH;
            table[0x4A] = Opcode::BLOBBASEFEE;
            table[0x4B] = Opcode::SLOTNUM;
            table[0x50] = Opcode::POP;
            table[0x56] = Opcode::JUMP;
            table[0x57] = Opcode::JUMPI;
            table[0x58] = Opcode::PC;
            table[0x5B] = Opcode::JUMPDEST;
            table[0x5F] = Opcode::PUSH0;
            table[0x60] = Opcode::PUSH1;
            table[0x61] = Opcode::PUSH2;
            table[0x62] = Opcode::PUSH3;
            table[0x63] = Opcode::PUSH4;
            table[0x64] = Opcode::PUSH5;
            table[0x65] = Opcode::PUSH6;
            table[0x66] = Opcode::PUSH7;
            table[0x67] = Opcode::PUSH8;
            table[0x68] = Opcode::PUSH9;
            table[0x69] = Opcode::PUSH10;
            table[0x6A] = Opcode::PUSH11;
            table[0x6B] = Opcode::PUSH12;
            table[0x6C] = Opcode::PUSH13;
            table[0x6D] = Opcode::PUSH14;
            table[0x6E] = Opcode::PUSH15;
            table[0x6F] = Opcode::PUSH16;
            table[0x70] = Opcode::PUSH17;
            table[0x71] = Opcode::PUSH18;
            table[0x72] = Opcode::PUSH19;
            table[0x73] = Opcode::PUSH20;
            table[0x74] = Opcode::PUSH21;
            table[0x75] = Opcode::PUSH22;
            table[0x76] = Opcode::PUSH23;
            table[0x77] = Opcode::PUSH24;
            table[0x78] = Opcode::PUSH25;
            table[0x79] = Opcode::PUSH26;
            table[0x7A] = Opcode::PUSH27;
            table[0x7B] = Opcode::PUSH28;
            table[0x7C] = Opcode::PUSH29;
            table[0x7D] = Opcode::PUSH30;
            table[0x7E] = Opcode::PUSH31;
            table[0x7F] = Opcode::PUSH32;
            table[0x80] = Opcode::DUP1;
            table[0x81] = Opcode::DUP2;
            table[0x82] = Opcode::DUP3;
            table[0x83] = Opcode::DUP4;
            table[0x84] = Opcode::DUP5;
            table[0x85] = Opcode::DUP6;
            table[0x86] = Opcode::DUP7;
            table[0x87] = Opcode::DUP8;
            table[0x88] = Opcode::DUP9;
            table[0x89] = Opcode::DUP10;
            table[0x8A] = Opcode::DUP11;
            table[0x8B] = Opcode::DUP12;
            table[0x8C] = Opcode::DUP13;
            table[0x8D] = Opcode::DUP14;
            table[0x8E] = Opcode::DUP15;
            table[0x8F] = Opcode::DUP16;
            table[0x90] = Opcode::SWAP1;
            table[0x91] = Opcode::SWAP2;
            table[0x92] = Opcode::SWAP3;
            table[0x93] = Opcode::SWAP4;
            table[0x94] = Opcode::SWAP5;
            table[0x95] = Opcode::SWAP6;
            table[0x96] = Opcode::SWAP7;
            table[0x97] = Opcode::SWAP8;
            table[0x98] = Opcode::SWAP9;
            table[0x99] = Opcode::SWAP10;
            table[0x9A] = Opcode::SWAP11;
            table[0x9B] = Opcode::SWAP12;
            table[0x9C] = Opcode::SWAP13;
            table[0x9D] = Opcode::SWAP14;
            table[0x9E] = Opcode::SWAP15;
            table[0x9F] = Opcode::SWAP16;
            table[0xA0] = Opcode::LOG0;
            table[0xA1] = Opcode::LOG1;
            table[0xA2] = Opcode::LOG2;
            table[0xA3] = Opcode::LOG3;
            table[0xA4] = Opcode::LOG4;
            table[0xAA] = Opcode::APPROVE;
            table[0xB0] = Opcode::TXPARAM;
            table[0xB1] = Opcode::FRAMEDATALOAD;
            table[0xB2] = Opcode::FRAMEDATACOPY;
            table[0xB3] = Opcode::FRAMEPARAM;
            table[0xB4] = Opcode::SIGPARAM;
            table[0xB5] = Opcode::SIGDATACOPY;
            table[0x51] = Opcode::MLOAD;
            table[0x52] = Opcode::MSTORE;
            table[0x53] = Opcode::MSTORE8;
            table[0x54] = Opcode::SLOAD;
            table[0x55] = Opcode::SSTORE;
            table[0x59] = Opcode::MSIZE;
            table[0x5A] = Opcode::GAS;
            table[0x5E] = Opcode::MCOPY;
            table[0x5C] = Opcode::TLOAD;
            table[0x5D] = Opcode::TSTORE;
            table[0xE6] = Opcode::DUPN;
            table[0xE7] = Opcode::SWAPN;
            table[0xE8] = Opcode::EXCHANGE;
            table[0xF0] = Opcode::CREATE;
            table[0xF1] = Opcode::CALL;
            table[0xF2] = Opcode::CALLCODE;
            table[0xF3] = Opcode::RETURN;
            table[0xF5] = Opcode::CREATE2;
            table[0xF4] = Opcode::DELEGATECALL;
            table[0xFA] = Opcode::STATICCALL;
            table[0xFD] = Opcode::REVERT;
            table[0xFF] = Opcode::SELFDESTRUCT;

            table
        };
        #[expect(clippy::indexing_slicing)] // can never happen
        OPCODE_TABLE[byte as usize]
    }
}

impl From<Opcode> for u8 {
    #[allow(clippy::as_conversions)]
    fn from(opcode: Opcode) -> Self {
        opcode as u8
    }
}

impl From<Opcode> for usize {
    #[allow(clippy::as_conversions)]
    fn from(opcode: Opcode) -> Self {
        opcode as usize
    }
}

/// Represents an opcode function handler.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OpCodeFn(fn(&mut VM<'_>, &mut OnceCell<VMError>) -> OpcodeResult);

impl OpCodeFn {
    pub const fn new<T>() -> Self
    where
        T: OpcodeHandler,
    {
        Self(Self::wrap::<T>)
    }

    /// Call the opcode handler.
    #[inline(always)]
    pub fn call(self, vm: &mut VM<'_>, error: &mut OnceCell<VMError>) -> OpcodeResult {
        (self.0)(vm, error)
    }

    fn wrap<T>(vm: &mut VM<'_>, error: &mut OnceCell<VMError>) -> OpcodeResult
    where
        T: OpcodeHandler,
    {
        T::eval(vm).unwrap_or_else(|err| {
            _ = error.set(err);
            OpcodeResult::Halt
        })
    }
}

impl<'a> VM<'a> {
    /// Returns the opcode lookup function-pointer table for the given fork.
    ///
    /// The per-fork tables are `const`-evaluated once into process statics (the builders below
    /// are all `const fn`), so this is a branch returning a shared `&'static` reference — no
    /// per-tx rebuild or 2 KB copy into the VM. `fork` is constant within a block, so every tx
    /// in a block resolves to the same table. This is faster than a conventional match.
    #[allow(clippy::as_conversions, clippy::indexing_slicing)]
    pub(crate) fn build_opcode_table(fork: Fork) -> &'static [OpCodeFn; 256] {
        // Built once at compile time; immutable, so sharing across all VMs is trivially safe.
        // Instantiated with `'static` so the initializers don't reference the impl's `'a`.
        static HEGOTA: [OpCodeFn; 256] = VM::<'static>::build_opcode_table_hegota();
        static AMSTERDAM: [OpCodeFn; 256] = VM::<'static>::build_opcode_table_amsterdam();
        static OSAKA: [OpCodeFn; 256] = VM::<'static>::build_opcode_table_osaka();
        static PRE_OSAKA: [OpCodeFn; 256] = VM::<'static>::build_opcode_table_pre_osaka();
        static PRE_CANCUN: [OpCodeFn; 256] = VM::<'static>::build_opcode_table_pre_cancun();
        static PRE_SHANGHAI: [OpCodeFn; 256] = VM::<'static>::build_opcode_table_pre_shanghai();

        if fork >= Fork::Hegota {
            &HEGOTA
        } else if fork >= Fork::Amsterdam {
            &AMSTERDAM
        } else if fork >= Fork::Osaka {
            &OSAKA
        } else if fork >= Fork::Cancun {
            &PRE_OSAKA
        } else if fork >= Fork::Shanghai {
            &PRE_CANCUN
        } else {
            &PRE_SHANGHAI
        }
    }

    #[allow(clippy::as_conversions, clippy::indexing_slicing)]
    const fn build_opcode_table_pre_shanghai() -> [OpCodeFn; 256] {
        let mut opcode_table: [OpCodeFn; 256] = [OpCodeFn::new::<OpInvalidHandler>(); 256];

        opcode_table[Opcode::STOP as usize] = OpCodeFn::new::<OpStopHandler>();
        opcode_table[Opcode::MLOAD as usize] = OpCodeFn::new::<OpMLoadHandler>();
        opcode_table[Opcode::MSTORE as usize] = OpCodeFn::new::<OpMStoreHandler>();
        opcode_table[Opcode::MSTORE8 as usize] = OpCodeFn::new::<OpMStore8Handler>();
        opcode_table[Opcode::JUMP as usize] = OpCodeFn::new::<OpJumpHandler>();
        opcode_table[Opcode::SLOAD as usize] = OpCodeFn::new::<OpSLoadHandler>();
        opcode_table[Opcode::SSTORE as usize] = OpCodeFn::new::<OpSStoreHandler>();
        opcode_table[Opcode::MSIZE as usize] = OpCodeFn::new::<OpMSizeHandler>();
        opcode_table[Opcode::GAS as usize] = OpCodeFn::new::<OpGasHandler>();
        opcode_table[Opcode::PUSH1 as usize] = OpCodeFn::new::<OpPushHandler<1>>();
        opcode_table[Opcode::PUSH2 as usize] = OpCodeFn::new::<OpPushHandler<2>>();
        opcode_table[Opcode::PUSH3 as usize] = OpCodeFn::new::<OpPushHandler<3>>();
        opcode_table[Opcode::PUSH4 as usize] = OpCodeFn::new::<OpPushHandler<4>>();
        opcode_table[Opcode::PUSH5 as usize] = OpCodeFn::new::<OpPushHandler<5>>();
        opcode_table[Opcode::PUSH6 as usize] = OpCodeFn::new::<OpPushHandler<6>>();
        opcode_table[Opcode::PUSH7 as usize] = OpCodeFn::new::<OpPushHandler<7>>();
        opcode_table[Opcode::PUSH8 as usize] = OpCodeFn::new::<OpPushHandler<8>>();
        opcode_table[Opcode::PUSH9 as usize] = OpCodeFn::new::<OpPushHandler<9>>();
        opcode_table[Opcode::PUSH10 as usize] = OpCodeFn::new::<OpPushHandler<10>>();
        opcode_table[Opcode::PUSH11 as usize] = OpCodeFn::new::<OpPushHandler<11>>();
        opcode_table[Opcode::PUSH12 as usize] = OpCodeFn::new::<OpPushHandler<12>>();
        opcode_table[Opcode::PUSH13 as usize] = OpCodeFn::new::<OpPushHandler<13>>();
        opcode_table[Opcode::PUSH14 as usize] = OpCodeFn::new::<OpPushHandler<14>>();
        opcode_table[Opcode::PUSH15 as usize] = OpCodeFn::new::<OpPushHandler<15>>();
        opcode_table[Opcode::PUSH16 as usize] = OpCodeFn::new::<OpPushHandler<16>>();
        opcode_table[Opcode::PUSH17 as usize] = OpCodeFn::new::<OpPushHandler<17>>();
        opcode_table[Opcode::PUSH18 as usize] = OpCodeFn::new::<OpPushHandler<18>>();
        opcode_table[Opcode::PUSH19 as usize] = OpCodeFn::new::<OpPushHandler<19>>();
        opcode_table[Opcode::PUSH20 as usize] = OpCodeFn::new::<OpPushHandler<20>>();
        opcode_table[Opcode::PUSH21 as usize] = OpCodeFn::new::<OpPushHandler<21>>();
        opcode_table[Opcode::PUSH22 as usize] = OpCodeFn::new::<OpPushHandler<22>>();
        opcode_table[Opcode::PUSH23 as usize] = OpCodeFn::new::<OpPushHandler<23>>();
        opcode_table[Opcode::PUSH24 as usize] = OpCodeFn::new::<OpPushHandler<24>>();
        opcode_table[Opcode::PUSH25 as usize] = OpCodeFn::new::<OpPushHandler<25>>();
        opcode_table[Opcode::PUSH26 as usize] = OpCodeFn::new::<OpPushHandler<26>>();
        opcode_table[Opcode::PUSH27 as usize] = OpCodeFn::new::<OpPushHandler<27>>();
        opcode_table[Opcode::PUSH28 as usize] = OpCodeFn::new::<OpPushHandler<28>>();
        opcode_table[Opcode::PUSH29 as usize] = OpCodeFn::new::<OpPushHandler<29>>();
        opcode_table[Opcode::PUSH30 as usize] = OpCodeFn::new::<OpPushHandler<30>>();
        opcode_table[Opcode::PUSH31 as usize] = OpCodeFn::new::<OpPushHandler<31>>();
        opcode_table[Opcode::PUSH32 as usize] = OpCodeFn::new::<OpPushHandler<32>>();

        opcode_table[Opcode::DUP1 as usize] = OpCodeFn::new::<OpDupHandler<0>>();
        opcode_table[Opcode::DUP2 as usize] = OpCodeFn::new::<OpDupHandler<1>>();
        opcode_table[Opcode::DUP3 as usize] = OpCodeFn::new::<OpDupHandler<2>>();
        opcode_table[Opcode::DUP4 as usize] = OpCodeFn::new::<OpDupHandler<3>>();
        opcode_table[Opcode::DUP5 as usize] = OpCodeFn::new::<OpDupHandler<4>>();
        opcode_table[Opcode::DUP6 as usize] = OpCodeFn::new::<OpDupHandler<5>>();
        opcode_table[Opcode::DUP7 as usize] = OpCodeFn::new::<OpDupHandler<6>>();
        opcode_table[Opcode::DUP8 as usize] = OpCodeFn::new::<OpDupHandler<7>>();
        opcode_table[Opcode::DUP9 as usize] = OpCodeFn::new::<OpDupHandler<8>>();
        opcode_table[Opcode::DUP10 as usize] = OpCodeFn::new::<OpDupHandler<9>>();
        opcode_table[Opcode::DUP11 as usize] = OpCodeFn::new::<OpDupHandler<10>>();
        opcode_table[Opcode::DUP12 as usize] = OpCodeFn::new::<OpDupHandler<11>>();
        opcode_table[Opcode::DUP13 as usize] = OpCodeFn::new::<OpDupHandler<12>>();
        opcode_table[Opcode::DUP14 as usize] = OpCodeFn::new::<OpDupHandler<13>>();
        opcode_table[Opcode::DUP15 as usize] = OpCodeFn::new::<OpDupHandler<14>>();
        opcode_table[Opcode::DUP16 as usize] = OpCodeFn::new::<OpDupHandler<15>>();

        opcode_table[Opcode::SWAP1 as usize] = OpCodeFn::new::<OpSwapHandler<1>>();
        opcode_table[Opcode::SWAP2 as usize] = OpCodeFn::new::<OpSwapHandler<2>>();
        opcode_table[Opcode::SWAP3 as usize] = OpCodeFn::new::<OpSwapHandler<3>>();
        opcode_table[Opcode::SWAP4 as usize] = OpCodeFn::new::<OpSwapHandler<4>>();
        opcode_table[Opcode::SWAP5 as usize] = OpCodeFn::new::<OpSwapHandler<5>>();
        opcode_table[Opcode::SWAP6 as usize] = OpCodeFn::new::<OpSwapHandler<6>>();
        opcode_table[Opcode::SWAP7 as usize] = OpCodeFn::new::<OpSwapHandler<7>>();
        opcode_table[Opcode::SWAP8 as usize] = OpCodeFn::new::<OpSwapHandler<8>>();
        opcode_table[Opcode::SWAP9 as usize] = OpCodeFn::new::<OpSwapHandler<9>>();
        opcode_table[Opcode::SWAP10 as usize] = OpCodeFn::new::<OpSwapHandler<10>>();
        opcode_table[Opcode::SWAP11 as usize] = OpCodeFn::new::<OpSwapHandler<11>>();
        opcode_table[Opcode::SWAP12 as usize] = OpCodeFn::new::<OpSwapHandler<12>>();
        opcode_table[Opcode::SWAP13 as usize] = OpCodeFn::new::<OpSwapHandler<13>>();
        opcode_table[Opcode::SWAP14 as usize] = OpCodeFn::new::<OpSwapHandler<14>>();
        opcode_table[Opcode::SWAP15 as usize] = OpCodeFn::new::<OpSwapHandler<15>>();
        opcode_table[Opcode::SWAP16 as usize] = OpCodeFn::new::<OpSwapHandler<16>>();
        opcode_table[Opcode::POP as usize] = OpCodeFn::new::<OpPopHandler>();
        opcode_table[Opcode::ADD as usize] = OpCodeFn::new::<OpAddHandler>();
        opcode_table[Opcode::MUL as usize] = OpCodeFn::new::<OpMulHandler>();
        opcode_table[Opcode::SUB as usize] = OpCodeFn::new::<OpSubHandler>();
        opcode_table[Opcode::DIV as usize] = OpCodeFn::new::<OpDivHandler>();
        opcode_table[Opcode::SDIV as usize] = OpCodeFn::new::<OpSDivHandler>();
        opcode_table[Opcode::MOD as usize] = OpCodeFn::new::<OpModHandler>();
        opcode_table[Opcode::SMOD as usize] = OpCodeFn::new::<OpSModHandler>();
        opcode_table[Opcode::ADDMOD as usize] = OpCodeFn::new::<OpAddModHandler>();
        opcode_table[Opcode::MULMOD as usize] = OpCodeFn::new::<OpMulModHandler>();
        opcode_table[Opcode::EXP as usize] = OpCodeFn::new::<OpExpHandler>();
        opcode_table[Opcode::CALL as usize] = OpCodeFn::new::<OpCallHandler>();
        opcode_table[Opcode::CALLCODE as usize] = OpCodeFn::new::<OpCallCodeHandler>();
        opcode_table[Opcode::RETURN as usize] = OpCodeFn::new::<OpReturnHandler>();
        opcode_table[Opcode::DELEGATECALL as usize] = OpCodeFn::new::<OpDelegateCallHandler>();
        opcode_table[Opcode::STATICCALL as usize] = OpCodeFn::new::<OpStaticCallHandler>();
        opcode_table[Opcode::CREATE as usize] = OpCodeFn::new::<OpCreateHandler>();
        opcode_table[Opcode::CREATE2 as usize] = OpCodeFn::new::<OpCreate2Handler>();
        opcode_table[Opcode::JUMPI as usize] = OpCodeFn::new::<OpJumpIHandler>();
        opcode_table[Opcode::JUMPDEST as usize] = OpCodeFn::new::<OpJumpDestHandler>();
        opcode_table[Opcode::ADDRESS as usize] = OpCodeFn::new::<OpAddressHandler>();
        opcode_table[Opcode::ORIGIN as usize] = OpCodeFn::new::<OpOriginHandler>();
        opcode_table[Opcode::BALANCE as usize] = OpCodeFn::new::<OpBalanceHandler>();
        opcode_table[Opcode::CALLER as usize] = OpCodeFn::new::<OpCallerHandler>();
        opcode_table[Opcode::CALLVALUE as usize] = OpCodeFn::new::<OpCallValueHandler>();
        opcode_table[Opcode::CODECOPY as usize] = OpCodeFn::new::<OpCodeCopyHandler>();
        opcode_table[Opcode::SIGNEXTEND as usize] = OpCodeFn::new::<OpSignExtendHandler>();
        opcode_table[Opcode::LT as usize] = OpCodeFn::new::<OpLtHandler>();
        opcode_table[Opcode::GT as usize] = OpCodeFn::new::<OpGtHandler>();
        opcode_table[Opcode::SLT as usize] = OpCodeFn::new::<OpSLtHandler>();
        opcode_table[Opcode::SGT as usize] = OpCodeFn::new::<OpSGtHandler>();
        opcode_table[Opcode::EQ as usize] = OpCodeFn::new::<OpEqHandler>();
        opcode_table[Opcode::ISZERO as usize] = OpCodeFn::new::<OpIsZeroHandler>();
        opcode_table[Opcode::KECCAK256 as usize] = OpCodeFn::new::<OpKeccak256Handler>();
        opcode_table[Opcode::CALLDATALOAD as usize] = OpCodeFn::new::<OpCallDataLoadHandler>();
        opcode_table[Opcode::CALLDATASIZE as usize] = OpCodeFn::new::<OpCallDataSizeHandler>();
        opcode_table[Opcode::CALLDATACOPY as usize] = OpCodeFn::new::<OpCallDataCopyHandler>();
        opcode_table[Opcode::RETURNDATASIZE as usize] = OpCodeFn::new::<OpReturnDataSizeHandler>();
        opcode_table[Opcode::RETURNDATACOPY as usize] = OpCodeFn::new::<OpReturnDataCopyHandler>();
        opcode_table[Opcode::PC as usize] = OpCodeFn::new::<OpPcHandler>();
        opcode_table[Opcode::BLOCKHASH as usize] = OpCodeFn::new::<OpBlockHashHandler>();
        opcode_table[Opcode::COINBASE as usize] = OpCodeFn::new::<OpCoinbaseHandler>();
        opcode_table[Opcode::TIMESTAMP as usize] = OpCodeFn::new::<OpTimestampHandler>();
        opcode_table[Opcode::NUMBER as usize] = OpCodeFn::new::<OpNumberHandler>();
        opcode_table[Opcode::PREVRANDAO as usize] = OpCodeFn::new::<OpPrevRandaoHandler>();
        opcode_table[Opcode::GASLIMIT as usize] = OpCodeFn::new::<OpGasLimitHandler>();
        opcode_table[Opcode::CHAINID as usize] = OpCodeFn::new::<OpChainIdHandler>();
        opcode_table[Opcode::BASEFEE as usize] = OpCodeFn::new::<OpBaseFeeHandler>();
        opcode_table[Opcode::AND as usize] = OpCodeFn::new::<OpAndHandler>();
        opcode_table[Opcode::OR as usize] = OpCodeFn::new::<OpOrHandler>();
        opcode_table[Opcode::XOR as usize] = OpCodeFn::new::<OpXorHandler>();
        opcode_table[Opcode::NOT as usize] = OpCodeFn::new::<OpNotHandler>();
        opcode_table[Opcode::BYTE as usize] = OpCodeFn::new::<OpByteHandler>();
        opcode_table[Opcode::SHL as usize] = OpCodeFn::new::<OpShlHandler>();
        opcode_table[Opcode::SHR as usize] = OpCodeFn::new::<OpShrHandler>();
        opcode_table[Opcode::SAR as usize] = OpCodeFn::new::<OpSarHandler>();
        opcode_table[Opcode::SELFBALANCE as usize] = OpCodeFn::new::<OpSelfBalanceHandler>();
        opcode_table[Opcode::CODESIZE as usize] = OpCodeFn::new::<OpCodeSizeHandler>();
        opcode_table[Opcode::GASPRICE as usize] = OpCodeFn::new::<OpGasPriceHandler>();
        opcode_table[Opcode::EXTCODESIZE as usize] = OpCodeFn::new::<OpExtCodeSizeHandler>();
        opcode_table[Opcode::EXTCODECOPY as usize] = OpCodeFn::new::<OpExtCodeCopyHandler>();
        opcode_table[Opcode::EXTCODEHASH as usize] = OpCodeFn::new::<OpExtCodeHashHandler>();
        opcode_table[Opcode::REVERT as usize] = OpCodeFn::new::<OpRevertHandler>();
        opcode_table[Opcode::INVALID as usize] = OpCodeFn::new::<OpInvalidHandler>();
        opcode_table[Opcode::SELFDESTRUCT as usize] = OpCodeFn::new::<OpSelfDestructHandler>();

        opcode_table[Opcode::LOG0 as usize] = OpCodeFn::new::<OpLogHandler<0>>();
        opcode_table[Opcode::LOG1 as usize] = OpCodeFn::new::<OpLogHandler<1>>();
        opcode_table[Opcode::LOG2 as usize] = OpCodeFn::new::<OpLogHandler<2>>();
        opcode_table[Opcode::LOG3 as usize] = OpCodeFn::new::<OpLogHandler<3>>();
        opcode_table[Opcode::LOG4 as usize] = OpCodeFn::new::<OpLogHandler<4>>();

        opcode_table
    }

    #[allow(clippy::as_conversions, clippy::indexing_slicing)]
    const fn build_opcode_table_pre_cancun() -> [OpCodeFn; 256] {
        let mut opcode_table: [OpCodeFn; 256] = Self::build_opcode_table_pre_shanghai();

        // [EIP-3855] - PUSH0 is only available from SHANGHAI
        opcode_table[Opcode::PUSH0 as usize] = OpCodeFn::new::<OpPush0Handler>();

        opcode_table
    }

    #[allow(clippy::as_conversions, clippy::indexing_slicing)]
    const fn build_opcode_table_pre_osaka() -> [OpCodeFn; 256] {
        const {
            let mut opcode_table: [OpCodeFn; 256] = Self::build_opcode_table_pre_cancun();

            // [EIP-5656] - MCOPY is only available from CANCUN
            opcode_table[Opcode::MCOPY as usize] = OpCodeFn::new::<OpMCopyHandler>();

            // [EIP-1153] - TLOAD is only available from CANCUN
            opcode_table[Opcode::TLOAD as usize] = OpCodeFn::new::<OpTLoadHandler>();
            opcode_table[Opcode::TSTORE as usize] = OpCodeFn::new::<OpTStoreHandler>();

            // [EIP-7516] - BLOBBASEFEE is only available from CANCUN
            opcode_table[Opcode::BLOBBASEFEE as usize] = OpCodeFn::new::<OpBlobBaseFeeHandler>();
            // [EIP-4844] - BLOBHASH is only available from CANCUN
            opcode_table[Opcode::BLOBHASH as usize] = OpCodeFn::new::<OpBlobHashHandler>();

            opcode_table
        }
    }

    #[allow(clippy::as_conversions, clippy::indexing_slicing)]
    const fn build_opcode_table_osaka() -> [OpCodeFn; 256] {
        let mut opcode_table: [OpCodeFn; 256] = Self::build_opcode_table_pre_osaka();

        opcode_table[Opcode::CLZ as usize] = OpCodeFn::new::<OpClzHandler>();

        opcode_table
    }

    #[expect(clippy::as_conversions, clippy::indexing_slicing)]
    const fn build_opcode_table_amsterdam() -> [OpCodeFn; 256] {
        let mut opcode_table: [OpCodeFn; 256] = Self::build_opcode_table_osaka();

        // EIP-8024 opcodes
        opcode_table[Opcode::DUPN as usize] = OpCodeFn::new::<OpDupNHandler>();
        opcode_table[Opcode::SWAPN as usize] = OpCodeFn::new::<OpSwapNHandler>();
        opcode_table[Opcode::EXCHANGE as usize] = OpCodeFn::new::<OpExchangeHandler>();
        // EIP-7843 opcode
        opcode_table[Opcode::SLOTNUM as usize] = OpCodeFn::new::<OpSlotNumHandler>();
        opcode_table
    }

    #[expect(clippy::as_conversions, clippy::indexing_slicing)]
    const fn build_opcode_table_hegota() -> [OpCodeFn; 256] {
        let mut opcode_table: [OpCodeFn; 256] = Self::build_opcode_table_amsterdam();

        // EIP-8141 Frame Transaction opcodes (Hegota)
        opcode_table[Opcode::APPROVE as usize] = OpCodeFn::new::<OpApproveHandler>();
        opcode_table[Opcode::TXPARAM as usize] = OpCodeFn::new::<OpTxParamHandler>();
        opcode_table[Opcode::FRAMEDATALOAD as usize] = OpCodeFn::new::<OpFrameDataLoadHandler>();
        opcode_table[Opcode::FRAMEDATACOPY as usize] = OpCodeFn::new::<OpFrameDataCopyHandler>();
        opcode_table[Opcode::FRAMEPARAM as usize] = OpCodeFn::new::<OpFrameParamHandler>();
        opcode_table[Opcode::SIGPARAM as usize] = OpCodeFn::new::<OpSigParamHandler>();
        opcode_table[Opcode::SIGDATACOPY as usize] = OpCodeFn::new::<OpSigDataCopyHandler>();

        opcode_table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(
        clippy::indexing_slicing,
        reason = "fixed 256-entry table indexed by u8"
    )]
    fn frame_opcodes_not_installed_before_hegota() {
        fn same_handler(a: OpCodeFn, b: OpCodeFn) -> bool {
            // Compare handler identity by fn-pointer address without an `as`
            // cast (the workspace denies clippy::as_conversions).
            std::ptr::fn_addr_eq(a.0, b.0)
        }
        // 0xEF is never assigned in any table -> it holds the invalid handler.
        for fork in [Fork::Osaka, Fork::Amsterdam] {
            let table = VM::build_opcode_table(fork);
            for byte in [0xAAusize, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5] {
                assert!(
                    same_handler(table[byte], table[0xEF]),
                    "frame opcode {byte:#x} must be invalid at {fork:?}"
                );
            }
        }
        let hegota = VM::build_opcode_table(Fork::Hegota);
        assert!(!same_handler(hegota[0xAA], hegota[0xEF]));
    }
}
