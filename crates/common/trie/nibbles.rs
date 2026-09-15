#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::{cmp, mem};

use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};

// ── SIMD nibble expansion ────────────────────────────────────────────────────
//
// The hot path during block execution converts 32-byte keccak keys to 64
// nibbles on every trie lookup / insert.  We replace the original flat_map
// iterator chain with a SIMD kernel that processes 16 or 32 bytes per cycle.

/// Expands each byte in `bytes` into two nibbles (high nibble first),
/// writing `bytes.len() * 2` bytes to the uninitialized `output` pointer.
///
/// # Safety
/// `output` must be valid for writes of at least `bytes.len() * 2` bytes.
#[inline]
#[allow(unsafe_code)]
unsafe fn expand_bytes_to_nibbles(bytes: &[u8], output: *mut u8) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: caller guarantees output is writable for bytes.len() * 2 bytes.
        unsafe { expand_bytes_to_nibbles_x86_64(bytes, output) };
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: caller guarantees output is writable for bytes.len() * 2 bytes.
        unsafe { expand_bytes_to_nibbles_aarch64(bytes, output) };
        return;
    }
    // Portable scalar fallback for other architectures.
    #[allow(unreachable_code)]
    // SAFETY: caller guarantees output is writable for bytes.len() * 2 bytes.
    unsafe {
        expand_bytes_to_nibbles_scalar(bytes, output)
    };
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[inline]
unsafe fn expand_bytes_to_nibbles_x86_64(bytes: &[u8], output: *mut u8) {
    use core::arch::x86_64::*;

    let n = bytes.len();
    let mut i = 0usize;

    // --- AVX2 path: 32 bytes → 64 nibbles per iteration ---
    // Enabled only when the compiler has +avx2 in target-feature
    // (set via .cargo/config.toml for the production x86_64-linux target).
    #[cfg(target_feature = "avx2")]
    // SAFETY: AVX2 is enabled at compile time via .cargo/config.toml target-feature.
    unsafe {
        let mask256 = _mm256_set1_epi8(0x0F_u8 as i8);
        while i + 32 <= n {
            // Load 32 input bytes.
            let v = _mm256_loadu_si256(bytes.as_ptr().add(i).cast::<__m256i>());
            // Extract high nibbles: shift each 16-bit word right by 4, then mask.
            let hi = _mm256_and_si256(_mm256_srli_epi16(v, 4), mask256);
            // Extract low nibbles.
            let lo = _mm256_and_si256(v, mask256);
            // Interleave hi/lo within each 128-bit lane.
            // _mm256_unpacklo_epi8 → [hi0,lo0,hi1,lo1,…,hi7,lo7 | hi16,lo16,…,hi23,lo23]
            // _mm256_unpackhi_epi8 → [hi8,lo8,…,hi15,lo15       | hi24,lo24,…,hi31,lo31]
            let unpack_lo = _mm256_unpacklo_epi8(hi, lo);
            let unpack_hi = _mm256_unpackhi_epi8(hi, lo);
            // Cross-lane permute to restore sequential byte order:
            //   out_lo = [lane0(unpack_lo), lane0(unpack_hi)] = bytes  0-15 nibbles
            //   out_hi = [lane1(unpack_lo), lane1(unpack_hi)] = bytes 16-31 nibbles
            let out_lo = _mm256_permute2x128_si256::<0x20>(unpack_lo, unpack_hi);
            let out_hi = _mm256_permute2x128_si256::<0x31>(unpack_lo, unpack_hi);
            _mm256_storeu_si256(output.add(i * 2).cast::<__m256i>(), out_lo);
            _mm256_storeu_si256(output.add(i * 2 + 32).cast::<__m256i>(), out_hi);
            i += 32;
        }
    }

    // --- SSE2 path: 16 bytes → 32 nibbles per iteration ---
    // SSE2 is part of the x86_64 baseline; no runtime check needed.
    // SAFETY: SSE2 is always available on x86_64; pointer arithmetic stays within bounds.
    unsafe {
        let mask128 = _mm_set1_epi8(0x0F_u8 as i8);
        while i + 16 <= n {
            let v = _mm_loadu_si128(bytes.as_ptr().add(i).cast::<__m128i>());
            let hi = _mm_and_si128(_mm_srli_epi16(v, 4), mask128);
            let lo = _mm_and_si128(v, mask128);
            let lo16 = _mm_unpacklo_epi8(hi, lo);
            let hi16 = _mm_unpackhi_epi8(hi, lo);
            _mm_storeu_si128(output.add(i * 2).cast::<__m128i>(), lo16);
            _mm_storeu_si128(output.add(i * 2 + 16).cast::<__m128i>(), hi16);
            i += 16;
        }

        // Scalar tail for remaining bytes (0-15).
        while i < n {
            let b = *bytes.get_unchecked(i);
            *output.add(i * 2) = b >> 4;
            *output.add(i * 2 + 1) = b & 0x0F;
            i += 1;
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[allow(unsafe_code)]
#[inline]
unsafe fn expand_bytes_to_nibbles_aarch64(bytes: &[u8], output: *mut u8) {
    use core::arch::aarch64::*;

    let n = bytes.len();
    let mut i = 0usize;

    // NEON is mandatory on aarch64; no runtime detection needed.
    // SAFETY: NEON is always available on aarch64; bounds are maintained by the loop guard.
    unsafe {
        let mask_0f = vdupq_n_u8(0x0F);
        while i + 16 <= n {
            let v = vld1q_u8(bytes.as_ptr().add(i));
            // vshrq_n_u8 shifts each 8-bit lane independently → high nibbles directly.
            let hi = vshrq_n_u8(v, 4);
            let lo = vandq_u8(v, mask_0f);
            // vzip1q_u8 / vzip2q_u8 interleave bytes from two vectors.
            let lo16 = vzip1q_u8(hi, lo); // [hi0,lo0,hi1,lo1,…,hi7,lo7]
            let hi16 = vzip2q_u8(hi, lo); // [hi8,lo8,…,hi15,lo15]
            vst1q_u8(output.add(i * 2), lo16);
            vst1q_u8(output.add(i * 2 + 16), hi16);
            i += 16;
        }

        // Scalar tail.
        while i < n {
            let b = *bytes.get_unchecked(i);
            *output.add(i * 2) = b >> 4;
            *output.add(i * 2 + 1) = b & 0x0F;
            i += 1;
        }
    }
}

#[allow(unsafe_code)]
#[inline]
unsafe fn expand_bytes_to_nibbles_scalar(bytes: &[u8], output: *mut u8) {
    // SAFETY: caller guarantees output is valid for bytes.len() * 2 bytes.
    unsafe {
        for (i, &b) in bytes.iter().enumerate() {
            *output.add(i * 2) = b >> 4;
            *output.add(i * 2 + 1) = b & 0x0F;
        }
    }
}

// ── SIMD nibble packing ──────────────────────────────────────────────────────
//
// pack_nibble_pairs combines pairs of nibbles [hi, lo, hi, lo, …] into bytes
// [(hi<<4)|lo, …].  This is the hot path inside encode_compact, called on every
// trie node when computing the Merkle root.
//
// Strategy: use SSSE3 _mm_maddubs_epi16 which does
//   result[i] = a[2i]*16 + a[2i+1]  (treating a as unsigned, b as signed)
// Setting b = [16, 1, 16, 1, …] gives the packed nibble byte for each pair.
// This is enabled when SSSE3 is available (always on x86-64-v3).

/// Packs pairs of nibbles in `nibbles` into bytes, writing to `output`.
/// `nibbles.len()` must be even.
///
/// # Safety
/// `output` must be writable for `nibbles.len() / 2` bytes.
#[inline]
#[allow(unsafe_code)]
unsafe fn pack_nibble_pairs(nibbles: &[u8], output: *mut u8) {
    debug_assert!(nibbles.len().is_multiple_of(2));
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { pack_nibble_pairs_x86_64(nibbles, output) };
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { pack_nibble_pairs_aarch64(nibbles, output) };
        return;
    }
    #[allow(unreachable_code)]
    unsafe {
        pack_nibble_pairs_scalar(nibbles, output)
    };
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[inline]
unsafe fn pack_nibble_pairs_x86_64(nibbles: &[u8], output: *mut u8) {
    let n = nibbles.len(); // always even
    let mut i = 0usize; // index into nibbles (steps of 32)
    let mut o = 0usize; // index into output (steps of 16)

    // SSSE3 path: 32 nibbles → 16 output bytes per iteration.
    // _mm_maddubs_epi16(a, b): result[k] = (a[2k]*b[2k] + a[2k+1]*b[2k+1]) as i16
    // With b=[16,1,16,1,...] and a=[hi,lo,...]: result[k] = hi*16 + lo
    #[cfg(target_feature = "ssse3")]
    // SAFETY: SSSE3 enabled at compile time; pointer arithmetic stays within bounds.
    unsafe {
        use core::arch::x86_64::*;
        // Multiplier: weight = [16, 1] repeated → multiply even nibble by 16, odd by 1
        let weights = _mm_set1_epi16(0x0110_u16 as i16); // bytes: [16, 1, 16, 1, ...]
        while i + 32 <= n {
            // Load 32 nibbles (16 pairs) in two 128-bit chunks.
            let lo_chunk = _mm_loadu_si128(nibbles.as_ptr().add(i).cast::<__m128i>());
            let hi_chunk = _mm_loadu_si128(nibbles.as_ptr().add(i + 16).cast::<__m128i>());
            // maddubs: [hi0*16+lo0, hi1*16+lo1, …, hi7*16+lo7] as 16-bit lanes
            let lo_packed = _mm_maddubs_epi16(lo_chunk, weights);
            let hi_packed = _mm_maddubs_epi16(hi_chunk, weights);
            // packus: saturate to u8 and pack both 8×i16 → 16×u8
            let result = _mm_packus_epi16(lo_packed, hi_packed);
            _mm_storeu_si128(output.add(o).cast::<__m128i>(), result);
            i += 32;
            o += 16;
        }
    }

    // Scalar tail (handles remaining pairs when n is not a multiple of 32,
    // or when SSSE3 is unavailable).
    unsafe {
        while i + 2 <= n {
            *output.add(o) = (*nibbles.get_unchecked(i) << 4) | *nibbles.get_unchecked(i + 1);
            i += 2;
            o += 1;
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[allow(unsafe_code)]
#[inline]
unsafe fn pack_nibble_pairs_aarch64(nibbles: &[u8], output: *mut u8) {
    use core::arch::aarch64::*;

    let n = nibbles.len();
    let mut i = 0usize;
    let mut o = 0usize;

    // SAFETY: NEON always available; bounds maintained by loop guard.
    unsafe {
        while i + 32 <= n {
            // Load 32 nibbles interleaved as [hi, lo] pairs.
            let v = vld2q_u8(nibbles.as_ptr().add(i));
            // v.0 = hi nibbles, v.1 = lo nibbles
            // Pack: (hi << 4) | lo
            let packed = vorrq_u8(vshlq_n_u8(v.0, 4), v.1);
            vst1q_u8(output.add(o), packed);
            i += 32;
            o += 16;
        }
        while i + 2 <= n {
            *output.add(o) = (*nibbles.get_unchecked(i) << 4) | *nibbles.get_unchecked(i + 1);
            i += 2;
            o += 1;
        }
    }
}

#[allow(unsafe_code)]
#[inline]
unsafe fn pack_nibble_pairs_scalar(nibbles: &[u8], output: *mut u8) {
    // SAFETY: caller ensures `output` is valid for nibbles.len()/2 bytes.
    unsafe {
        let mut o = 0usize;
        let mut i = 0usize;
        let n = nibbles.len();
        while i + 2 <= n {
            *output.add(o) = (*nibbles.get_unchecked(i) << 4) | *nibbles.get_unchecked(i + 1);
            i += 2;
            o += 1;
        }
    }
}
// ─────────────────────────────────────────────────────────────────────────────

// ── SIMD prefix comparison ───────────────────────────────────────────────────
//
// count_common_prefix finds the length of the longest common prefix of two
// byte slices.  The trie uses this on every insert/lookup to navigate branch
// nodes.  Using SIMD we can compare 16 (SSE2) or 32 (AVX2) bytes at once.

#[allow(unsafe_code)]
#[inline]
fn count_common_prefix(a: &[u8], b: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: x86_64 SIMD; bounds are maintained within the function.
        return unsafe { count_common_prefix_x86_64(a, b) };
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON enabled; bounds are maintained within the function.
        return unsafe { count_common_prefix_aarch64(a, b) };
    }
    #[allow(unreachable_code)]
    count_common_prefix_scalar(a, b)
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[inline]
unsafe fn count_common_prefix_x86_64(a: &[u8], b: &[u8]) -> usize {
    use core::arch::x86_64::*;

    let n = a.len().min(b.len());
    let mut i = 0usize;

    #[cfg(target_feature = "avx2")]
    // SAFETY: AVX2 enabled at compile time; pointer arithmetic stays within bounds.
    unsafe {
        while i + 32 <= n {
            let va = _mm256_loadu_si256(a.as_ptr().add(i).cast::<__m256i>());
            let vb = _mm256_loadu_si256(b.as_ptr().add(i).cast::<__m256i>());
            // Compare bytes: equal → 0xFF, else 0x00
            let eq = _mm256_cmpeq_epi8(va, vb);
            // Create a 32-bit mask where bit k = 1 iff byte k was equal.
            let mask = _mm256_movemask_epi8(eq) as u32;
            if mask != 0xFFFF_FFFF {
                // First differing byte is at bit position (trailing ones).
                return i + mask.trailing_ones() as usize;
            }
            i += 32;
        }
    }

    // SSE2 (16-byte chunks). SSE2 is x86_64 baseline.
    // SAFETY: SSE2 always available; bounds maintained by loop guard.
    unsafe {
        while i + 16 <= n {
            let va = _mm_loadu_si128(a.as_ptr().add(i).cast::<__m128i>());
            let vb = _mm_loadu_si128(b.as_ptr().add(i).cast::<__m128i>());
            let eq = _mm_cmpeq_epi8(va, vb);
            let mask = _mm_movemask_epi8(eq) as u16;
            if mask != 0xFFFF {
                return i + mask.trailing_ones() as usize;
            }
            i += 16;
        }
    }

    // Scalar tail.
    i + count_common_prefix_scalar(&a[i..n], &b[i..n])
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[allow(unsafe_code)]
#[inline]
unsafe fn count_common_prefix_aarch64(a: &[u8], b: &[u8]) -> usize {
    use core::arch::aarch64::*;

    let n = a.len().min(b.len());
    let mut i = 0usize;

    // SAFETY: NEON always available; pointer arithmetic stays within bounds.
    unsafe {
        while i + 16 <= n {
            let va = vld1q_u8(a.as_ptr().add(i));
            let vb = vld1q_u8(b.as_ptr().add(i));
            // vceqq_u8: equal lanes → 0xFF, else 0x00
            let eq = vceqq_u8(va, vb);
            // vminvq_u8: reduce to minimum; if all 0xFF then all bytes matched.
            if vminvq_u8(eq) == 0xFF {
                i += 16;
                continue;
            }
            // Find first non-matching byte by scanning the 16-byte window.
            let mut eq_arr = [0u8; 16];
            vst1q_u8(eq_arr.as_mut_ptr(), eq);
            for (j, &byte) in eq_arr.iter().enumerate() {
                if byte == 0 {
                    return i + j;
                }
            }
            unreachable!()
        }
    }

    i + count_common_prefix_scalar(&a[i..n], &b[i..n])
}

#[inline]
fn count_common_prefix_scalar(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}
// ─────────────────────────────────────────────────────────────────────────────

// TODO: move path-tracking logic somewhere else
// PERF: try using a stack-allocated array
/// Struct representing a list of nibbles (half-bytes)
#[derive(
    Debug,
    Clone,
    Default,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Deserialize,
    rkyv::Serialize,
    rkyv::Archive,
)]
pub struct Nibbles {
    data: Vec<u8>,
    /// Parts of the path that have already been consumed (used for tracking
    /// current position when visiting nodes). See `current()`.
    already_consumed: Vec<u8>,
}

// NOTE: custom impls to ignore the `already_consumed` field

impl PartialEq for Nibbles {
    fn eq(&self, other: &Nibbles) -> bool {
        self.data == other.data
    }
}

impl Eq for Nibbles {}

impl PartialOrd for Nibbles {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Nibbles {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.data.cmp(&other.data)
    }
}

impl core::hash::Hash for Nibbles {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl Nibbles {
    /// Create `Nibbles` from  hex-encoded nibbles
    pub const fn from_hex(hex: Vec<u8>) -> Self {
        Self {
            data: hex,
            already_consumed: vec![],
        }
    }

    /// Splits incoming bytes into nibbles and appends the leaf flag (a 16 nibble at the end)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self::from_raw(bytes, true)
    }

    /// Splits incoming bytes into nibbles and appends the leaf flag (a 16 nibble at the end) if is_leaf is true
    pub fn from_raw(bytes: &[u8], is_leaf: bool) -> Self {
        let extra = usize::from(is_leaf);
        let mut data = Vec::with_capacity(bytes.len() * 2 + extra);

        // SAFETY: we allocated at least `bytes.len() * 2` capacity (plus `extra`),
        // and we set_len to exactly `bytes.len() * 2` after the SIMD kernel fills them.
        #[allow(unsafe_code)]
        unsafe {
            expand_bytes_to_nibbles(bytes, data.as_mut_ptr());
            data.set_len(bytes.len() * 2);
        }

        if is_leaf {
            data.push(16);
        }

        Self {
            data,
            already_consumed: vec![],
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    /// Returns the amount of nibbles
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no nibbles
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// If `prefix` is a prefix of self, move the offset after
    /// the prefix and return true, otherwise return false.
    pub fn skip_prefix(&mut self, prefix: &Nibbles) -> bool {
        if self.len() >= prefix.len() && &self.data[..prefix.len()] == prefix.as_ref() {
            self.already_consumed.extend_from_slice(&prefix.data);
            self.data.drain(..prefix.len());
            true
        } else {
            false
        }
    }

    /// Compares self to another, comparing prefixes only in case of unequal lengths.
    pub fn compare_prefix(&self, prefix: &Nibbles) -> cmp::Ordering {
        if self.len() > prefix.len() {
            self.data[..prefix.len()].cmp(&prefix.data)
        } else {
            self.data[..].cmp(&prefix.data[..self.len()])
        }
    }

    /// Compares self to another and returns the shared nibble count (amount of nibbles that are equal, from the start)
    pub fn count_prefix(&self, other: &Nibbles) -> usize {
        count_common_prefix(self.as_ref(), other.as_ref())
    }

    /// Removes and returns the first nibble
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<u8> {
        (!self.is_empty()).then(|| {
            self.already_consumed.push(self.data[0]);
            self.data.remove(0)
        })
    }

    /// Removes and returns the first nibble if it is a suitable choice index (aka < 16)
    pub fn next_choice(&mut self) -> Option<usize> {
        self.next().filter(|choice| *choice < 16).map(usize::from)
    }

    /// Returns the nibbles after the given offset
    pub fn offset(&self, offset: usize) -> Nibbles {
        let mut already_consumed = Vec::with_capacity(self.already_consumed.len() + offset);
        already_consumed.extend_from_slice(&self.already_consumed);
        already_consumed.extend_from_slice(&self.data[..offset]);
        Nibbles {
            data: self.data[offset..].to_vec(),
            already_consumed,
        }
    }

    /// Returns the nibbles beween the start and end indexes
    pub fn slice(&self, start: usize, end: usize) -> Nibbles {
        Nibbles::from_hex(self.data[start..end].to_vec())
    }

    /// Extends the nibbles with another list of nibbles
    pub fn extend(&mut self, other: &Nibbles) {
        self.data.extend_from_slice(other.as_ref());
    }

    /// Return the nibble at the given index, will panic if the index is out of range
    pub fn at(&self, i: usize) -> usize {
        self.data[i] as usize
    }

    /// Inserts a nibble at the start
    pub fn prepend(&mut self, nibble: u8) {
        self.data.insert(0, nibble);
    }

    /// Inserts a nibble at the end
    pub fn append(&mut self, nibble: u8) {
        self.data.push(nibble);
    }

    /// Taken from https://github.com/citahub/cita_trie/blob/master/src/nibbles.rs#L56
    /// Encodes the nibbles in compact form
    #[allow(unsafe_code)]
    pub fn encode_compact(&self) -> Vec<u8> {
        let is_leaf = self.is_leaf();
        let mut hex = if is_leaf {
            &self.data[0..self.data.len() - 1]
        } else {
            &self.data[0..]
        };
        // node type    path length    |    prefix    hexchar
        // --------------------------------------------------
        // extension    even           |    0000      0x0
        // extension    odd            |    0001      0x1
        // leaf         even           |    0010      0x2
        // leaf         odd            |    0011      0x3
        let prefix_nibble = if hex.len() % 2 == 1 {
            let v = 0x10 + hex[0];
            hex = &hex[1..];
            v
        } else {
            0x00
        };

        let pair_count = hex.len() / 2;
        let mut compact = Vec::with_capacity(1 + pair_count);
        compact.push(prefix_nibble + if is_leaf { 0x20 } else { 0x00 });

        // SIMD-accelerated packing of nibble pairs → bytes.
        // SAFETY: compact has capacity for `pair_count` bytes beyond the one already pushed.
        // pack_nibble_pairs writes exactly `pair_count` bytes starting at offset 1;
        // set_len then exposes those initialized bytes.
        unsafe {
            let out_ptr = compact.as_mut_ptr().add(1);
            pack_nibble_pairs(hex, out_ptr);
            compact.set_len(1 + pair_count);
        }

        compact
    }

    /// Encodes the nibbles in compact form
    pub fn decode_compact(compact: &[u8]) -> Self {
        Self::from_hex(compact_to_hex(compact))
    }

    /// Returns true if the nibbles contain the leaf flag (16) at the end
    pub fn is_leaf(&self) -> bool {
        if self.is_empty() {
            false
        } else {
            self.data[self.data.len() - 1] == 16
        }
    }

    /// Combines the nibbles into bytes, trimming the leaf flag if necessary
    pub fn to_bytes(&self) -> Vec<u8> {
        // Trim leaf flag
        let data = if !self.is_empty() && self.is_leaf() {
            &self.data[..self.len() - 1]
        } else {
            &self.data[..]
        };
        // Combine nibbles into bytes
        data.chunks(2)
            .map(|chunk| match chunk.len() {
                1 => chunk[0] << 4,
                _ => chunk[0] << 4 | chunk[1],
            })
            .collect::<Vec<_>>()
    }

    /// Concatenates self and another Nibbles returning a new Nibbles
    pub fn concat(&self, other: &Nibbles) -> Nibbles {
        let mut data = Vec::with_capacity(self.data.len() + other.data.len());
        data.extend_from_slice(&self.data);
        data.extend_from_slice(&other.data);
        Nibbles {
            data,
            already_consumed: self.already_consumed.clone(),
        }
    }

    /// Returns a copy of self with the nibble added at the end
    pub fn append_new(&self, nibble: u8) -> Nibbles {
        let mut data = Vec::with_capacity(self.data.len() + 1);
        data.extend_from_slice(&self.data);
        data.push(nibble);
        Nibbles {
            data,
            already_consumed: self.already_consumed.clone(),
        }
    }

    /// Return already consumed parts of path
    pub fn current(&self) -> Nibbles {
        Nibbles {
            data: self.already_consumed.clone(),
            already_consumed: vec![],
        }
    }

    /// Empties `self.data` and returns the content
    pub fn take(&mut self) -> Self {
        Nibbles {
            data: mem::take(&mut self.data),
            already_consumed: mem::take(&mut self.already_consumed),
        }
    }
}

impl AsRef<[u8]> for Nibbles {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl RLPEncode for Nibbles {
    fn encode(&self, buf: &mut Vec<u8>) {
        Encoder::new(buf).encode_field(&self.data).finish();
    }
}

impl RLPDecode for Nibbles {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (data, decoder) = decoder.decode_field("data")?;
        Ok((
            Self {
                data,
                already_consumed: vec![],
            },
            decoder.finish()?,
        ))
    }
}

// Code taken from https://github.com/ethereum/go-ethereum/blob/a1093d98eb3260f2abf340903c2d968b2b891c11/trie/encoding.go#L82
fn compact_to_hex(compact: &[u8]) -> Vec<u8> {
    if compact.is_empty() {
        return vec![];
    }
    let mut base = keybytes_to_hex(compact);
    // delete terminator flag
    let end = if base[0] < 2 {
        base.len() - 1
    } else {
        base.len()
    };
    // apply odd flag
    let chop = 2 - (base[0] & 1) as usize;
    base.drain(..chop);
    base.truncate(end - chop);
    base
}

// Code taken from https://github.com/ethereum/go-ethereum/blob/a1093d98eb3260f2abf340903c2d968b2b891c11/trie/encoding.go#L96
fn keybytes_to_hex(keybytes: &[u8]) -> Vec<u8> {
    let nibble_count = keybytes.len() * 2;
    let mut nibbles = Vec::with_capacity(nibble_count + 1);

    // SAFETY: we just allocated `nibble_count` capacity; SIMD kernel fills them.
    #[allow(unsafe_code)]
    unsafe {
        expand_bytes_to_nibbles(keybytes, nibbles.as_mut_ptr());
        nibbles.set_len(nibble_count);
    }
    nibbles.push(16); // leaf terminator
    nibbles
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scalar reference for expand_bytes_to_nibbles (no SIMD).
    fn expand_bytes_scalar_ref(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().flat_map(|&b| [b >> 4, b & 0x0F]).collect()
    }

    /// Scalar reference for pack_nibble_pairs (no SIMD).
    fn pack_nibble_pairs_scalar_ref(nibbles: &[u8]) -> Vec<u8> {
        nibbles
            .chunks_exact(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    #[test]
    fn expand_bytes_to_nibbles_matches_scalar() {
        // Test edge-case lengths: 0, 1, 15, 16, 17, 31, 32, 33, 64
        for &len in &[0, 1, 2, 15, 16, 17, 31, 32, 33, 48, 64] {
            let input: Vec<u8> = (0..len).map(|i| (i * 37 + 13) as u8).collect();
            let expected = expand_bytes_scalar_ref(&input);

            let mut actual = vec![0u8; input.len() * 2];
            #[allow(unsafe_code)]
            unsafe {
                expand_bytes_to_nibbles(&input, actual.as_mut_ptr());
            }
            assert_eq!(actual, expected, "mismatch at input length {len}");
        }
    }

    #[test]
    fn pack_nibble_pairs_matches_scalar() {
        // Test edge-case pair counts: 0, 2, 14, 16, 30, 32, 34, 64
        for &nibble_count in &[0, 2, 4, 14, 16, 30, 32, 34, 48, 64] {
            let input: Vec<u8> = (0..nibble_count).map(|i| (i % 16) as u8).collect();
            let expected = pack_nibble_pairs_scalar_ref(&input);

            let mut actual = vec![0u8; nibble_count / 2];
            #[allow(unsafe_code)]
            unsafe {
                pack_nibble_pairs(&input, actual.as_mut_ptr());
            }
            assert_eq!(actual, expected, "mismatch at nibble count {nibble_count}");
        }
    }

    #[test]
    fn expand_then_pack_roundtrip() {
        for &len in &[0, 1, 16, 32, 33] {
            let input: Vec<u8> = (0..len).map(|i| (i * 53 + 7) as u8).collect();
            let mut nibbles = vec![0u8; input.len() * 2];
            #[allow(unsafe_code)]
            unsafe {
                expand_bytes_to_nibbles(&input, nibbles.as_mut_ptr());
            }

            let mut packed = vec![0u8; input.len()];
            #[allow(unsafe_code)]
            unsafe {
                pack_nibble_pairs(&nibbles, packed.as_mut_ptr());
            }
            assert_eq!(packed, input, "roundtrip failed at length {len}");
        }
    }

    #[test]
    fn count_common_prefix_correctness() {
        // Identical slices
        let a = vec![1u8, 2, 3, 4, 5];
        assert_eq!(count_common_prefix(&a, &a), 5);

        // No common prefix
        assert_eq!(count_common_prefix(&[1, 2, 3], &[4, 5, 6]), 0);

        // Partial match
        assert_eq!(count_common_prefix(&[1, 2, 3, 4], &[1, 2, 5, 6]), 2);

        // Empty
        assert_eq!(count_common_prefix(&[], &[1, 2]), 0);
        assert_eq!(count_common_prefix(&[1, 2], &[]), 0);
        assert_eq!(count_common_prefix(&[], &[]), 0);

        // Long match crossing SIMD boundaries (>16 bytes)
        let long_a: Vec<u8> = (0..33).collect();
        let mut long_b = long_a.clone();
        long_b[32] = 255;
        assert_eq!(count_common_prefix(&long_a, &long_b), 32);
    }

    #[test]
    fn from_raw_leaf_flag() {
        let bytes = &[0xAB, 0xCD];
        let with_leaf = Nibbles::from_raw(bytes, true);
        let without_leaf = Nibbles::from_raw(bytes, false);

        assert_eq!(with_leaf.data, vec![0x0A, 0x0B, 0x0C, 0x0D, 16]);
        assert_eq!(without_leaf.data, vec![0x0A, 0x0B, 0x0C, 0x0D]);
    }
}
