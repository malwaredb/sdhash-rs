use crate::{Sdbf, BF_CLASS_MASKS, BITS, BIT_COUNT_16};

use bytemuck::{try_cast_slice, try_cast_slice_mut, try_from_bytes_mut};
use lazy_static::lazy_static;

static mut BF_EST_CACHE: [[u16; 256]; 256] = [[0u16; 256]; 256];

/// Estimate number of expected matching bits
pub unsafe fn bf_match_est(m: u32, k: u32, s1: usize, s2: usize, common: u32) -> u32 {
    // This cache should work >99% of the time
    if common == 0 && BF_EST_CACHE[s1][s2] > 0 {
        return BF_EST_CACHE[s1][s2] as u32;
    }
    let ex = 1f64 - 1.0 / m as f64;

    let result = m as f64
        * (1.0 - ex.powi(k as i32 * s1 as i32) - ex.powi(k as i32 * 32)
            + ex.powi(k as i32 * (s1 as u32 + s2 as u32 - common) as i32))
        .round();
    BF_EST_CACHE[s1][s2] = result as u16;

    result as u32
}

/// Insert a SHA1 hash into a Bloom filter
pub fn bf_sha1_insert(bf: &mut [u8], bf_class: u8, sha1_hash: &mut [u32]) -> u32 {
    let mut insert_cnt = 0;
    let bit_mask = BF_CLASS_MASKS[bf_class as usize];
    for i in 0..5 {
        sha1_hash[i] &= bit_mask;
        let k = (sha1_hash[i] >> 3) as usize;
        if bf[k] & BITS[(sha1_hash[i] & 0x7) as usize] == 0 {
            insert_cnt += 1;
        }
        bf[k] |= BITS[(sha1_hash[i] & 0x7) as usize];
    }
    insert_cnt
}

/// bf_merge(): Performs bitwise OR on two BFs
pub fn bf_merge(base: &mut [u32], overlay: &[u32], size: usize) {
    for i in 0..size {
        base[i] |= overlay[i];
    }
}

/// Compute the number of common bits b/w two filters
/// todo: make it work with any size BF
pub fn bf_bitcount(bfilter_1: &[u8], bfilter_2: &[u8], bf_size: usize) -> u32 {
    let mut result = 0;
    let mut buff64 = [0u64; 32];

    let mut buff16 = try_cast_slice_mut::<u64, u16>(&mut buff64)
        .expect("bf_bitcount(): failed to convert &[u64] to &[u16]");

    let f1_64 = try_cast_slice::<u8, u64>(bfilter_1)
        .expect("bf_bitcount(): failed to convert &[u8] to &[u64]");

    let f2_64 = try_cast_slice::<u8, u64>(bfilter_2)
        .expect("bf_bitcount(): failed to convert &[u8] to &[u64]");

    let mut buff64 = try_cast_slice_mut::<u16, u64>(buff16)
        .expect("bf_bitcount(): failed to convert &[u16] back to to &[u64]");

    for i in 0..bf_size / 8 {
        buff64[i] = f1_64[i] & f2_64[i];
    }

    for i in 0..bf_size / 2 {
        result += BIT_COUNT_16[buff16[i] as usize] as u32;
    }
    result
}

/// Returns the number of elements in BF (handles both sequential & dd case).
pub fn get_elem_count(sdbf: &Sdbf, index: usize) -> u32 {
    if sdbf.elem_counts.is_empty() {
        if index < sdbf.bf_count as usize - 1 {
            sdbf.max_elem
        } else {
            sdbf.last_count
        }
    } else {
        // DD fork
        sdbf.elem_counts[index] as u32
    }
}

/// Computer the number of common bits (dot product) b/w two filters--conditional optimized version for 256-byte BFs.
/// * The conditional looks first at the dot product of the first 32/64/128 bytes; if it is less than the threshold,
/// * it returns 0; otherwise, proceeds with the rest of the computation.
pub fn bf_bitcount_cut_256(bfilter_1: &[u8], bfilter_2: &[u8], cut_off: u32, slack: i32) -> u32 {
    let mut result = 0u32;
    let mut buff64 = [0u64; 32];

    let f1_64 = try_cast_slice::<u8, u64>(bfilter_1)
        .expect("bf_bitcount_cut_256(): failed to convert &[u8] to &[u64]");

    let f2_64 = try_cast_slice::<u8, u64>(bfilter_2)
        .expect("bf_bitcount_cut_256(): failed to convert &[u8] to &[u64]");

    // Partial computation (1/8 of full computation):
    buff64[0] = f1_64[0] & f2_64[0];
    buff64[1] = f1_64[1] & f2_64[1];
    buff64[2] = f1_64[2] & f2_64[2];
    buff64[3] = f1_64[3] & f2_64[3];

    let mut buff16 = try_cast_slice_mut::<u64, u16>(&mut buff64)
        .expect("bf_bitcount_cut_256(): failed to convert &[u64] to &[u16]");

    result += BIT_COUNT_16[buff16[0] as usize] as u32;
    result += BIT_COUNT_16[buff16[1] as usize] as u32;
    result += BIT_COUNT_16[buff16[2] as usize] as u32;
    result += BIT_COUNT_16[buff16[3] as usize] as u32;
    result += BIT_COUNT_16[buff16[4] as usize] as u32;
    result += BIT_COUNT_16[buff16[5] as usize] as u32;
    result += BIT_COUNT_16[buff16[6] as usize] as u32;
    result += BIT_COUNT_16[buff16[7] as usize] as u32;
    result += BIT_COUNT_16[buff16[8] as usize] as u32;
    result += BIT_COUNT_16[buff16[9] as usize] as u32;
    result += BIT_COUNT_16[buff16[10] as usize] as u32;
    result += BIT_COUNT_16[buff16[11] as usize] as u32;
    result += BIT_COUNT_16[buff16[12] as usize] as u32;
    result += BIT_COUNT_16[buff16[13] as usize] as u32;
    result += BIT_COUNT_16[buff16[14] as usize] as u32;
    result += BIT_COUNT_16[buff16[15] as usize] as u32;

    // First shortcircuit for the computation
    if cut_off > 0 && (8 * result as i32 + slack) < cut_off as i32 {
        return 0;
    }

    let mut buff64 = try_cast_slice_mut::<u16, u64>(buff16)
        .expect("bf_bitcount_cut_256(): failed to convert &[u16] back to &[u64]");

    buff64[4] = f1_64[4] & f2_64[4];
    buff64[5] = f1_64[5] & f2_64[5];
    buff64[6] = f1_64[6] & f2_64[6];
    buff64[7] = f1_64[7] & f2_64[7];

    let mut buff16 = try_cast_slice_mut::<u64, u16>(buff64)
        .expect("bf_bitcount_cut_256(): failed to convert &[u64] to &[u16]");

    result += BIT_COUNT_16[buff16[16] as usize] as u32;
    result += BIT_COUNT_16[buff16[17] as usize] as u32;
    result += BIT_COUNT_16[buff16[18] as usize] as u32;
    result += BIT_COUNT_16[buff16[19] as usize] as u32;
    result += BIT_COUNT_16[buff16[20] as usize] as u32;
    result += BIT_COUNT_16[buff16[21] as usize] as u32;
    result += BIT_COUNT_16[buff16[22] as usize] as u32;
    result += BIT_COUNT_16[buff16[23] as usize] as u32;
    result += BIT_COUNT_16[buff16[24] as usize] as u32;
    result += BIT_COUNT_16[buff16[25] as usize] as u32;
    result += BIT_COUNT_16[buff16[26] as usize] as u32;
    result += BIT_COUNT_16[buff16[27] as usize] as u32;
    result += BIT_COUNT_16[buff16[28] as usize] as u32;
    result += BIT_COUNT_16[buff16[29] as usize] as u32;
    result += BIT_COUNT_16[buff16[30] as usize] as u32;
    result += BIT_COUNT_16[buff16[31] as usize] as u32;

    // Second shortcircuit for the computation
    if cut_off > 0 && (4 * result as i32 + slack) < cut_off as i32 {
        return 0;
    }

    let mut buff64 = try_cast_slice_mut::<u16, u64>(buff16)
        .expect("bf_bitcount_cut_256(): failed to convert &[u16] back to &[u64]");

    buff64[8] = f1_64[8] & f2_64[8];
    buff64[9] = f1_64[9] & f2_64[9];
    buff64[10] = f1_64[10] & f2_64[10];
    buff64[11] = f1_64[11] & f2_64[11];
    buff64[12] = f1_64[12] & f2_64[12];
    buff64[13] = f1_64[13] & f2_64[13];
    buff64[14] = f1_64[14] & f2_64[14];
    buff64[15] = f1_64[15] & f2_64[15];

    let mut buff16 = try_cast_slice_mut::<u64, u16>(buff64)
        .expect("bf_bitcount_cut_256(): failed to convert &[u64] to &[u16]");

    result += BIT_COUNT_16[buff16[32] as usize] as u32;
    result += BIT_COUNT_16[buff16[33] as usize] as u32;
    result += BIT_COUNT_16[buff16[34] as usize] as u32;
    result += BIT_COUNT_16[buff16[35] as usize] as u32;
    result += BIT_COUNT_16[buff16[36] as usize] as u32;
    result += BIT_COUNT_16[buff16[37] as usize] as u32;
    result += BIT_COUNT_16[buff16[38] as usize] as u32;
    result += BIT_COUNT_16[buff16[39] as usize] as u32;
    result += BIT_COUNT_16[buff16[40] as usize] as u32;
    result += BIT_COUNT_16[buff16[41] as usize] as u32;
    result += BIT_COUNT_16[buff16[42] as usize] as u32;
    result += BIT_COUNT_16[buff16[43] as usize] as u32;
    result += BIT_COUNT_16[buff16[44] as usize] as u32;
    result += BIT_COUNT_16[buff16[45] as usize] as u32;
    result += BIT_COUNT_16[buff16[46] as usize] as u32;
    result += BIT_COUNT_16[buff16[47] as usize] as u32;
    result += BIT_COUNT_16[buff16[48] as usize] as u32;
    result += BIT_COUNT_16[buff16[49] as usize] as u32;
    result += BIT_COUNT_16[buff16[50] as usize] as u32;
    result += BIT_COUNT_16[buff16[51] as usize] as u32;
    result += BIT_COUNT_16[buff16[52] as usize] as u32;
    result += BIT_COUNT_16[buff16[53] as usize] as u32;
    result += BIT_COUNT_16[buff16[54] as usize] as u32;
    result += BIT_COUNT_16[buff16[55] as usize] as u32;
    result += BIT_COUNT_16[buff16[56] as usize] as u32;
    result += BIT_COUNT_16[buff16[57] as usize] as u32;
    result += BIT_COUNT_16[buff16[58] as usize] as u32;
    result += BIT_COUNT_16[buff16[59] as usize] as u32;
    result += BIT_COUNT_16[buff16[60] as usize] as u32;
    result += BIT_COUNT_16[buff16[61] as usize] as u32;
    result += BIT_COUNT_16[buff16[62] as usize] as u32;
    result += BIT_COUNT_16[buff16[63] as usize] as u32;

    // Third shortcircuit for the computation
    if cut_off > 0 && (2 * result as i32 + slack) < cut_off as i32 {
        return 0;
    }

    let mut buff64 = try_cast_slice_mut::<u16, u64>(buff16)
        .expect("bf_bitcount_cut_256(): failed to convert &[u16] back to &[u64]");

    buff64[16] = f1_64[16] & f2_64[16];
    buff64[17] = f1_64[17] & f2_64[17];
    buff64[18] = f1_64[18] & f2_64[18];
    buff64[19] = f1_64[19] & f2_64[19];
    buff64[20] = f1_64[20] & f2_64[20];
    buff64[21] = f1_64[21] & f2_64[21];
    buff64[22] = f1_64[22] & f2_64[22];
    buff64[23] = f1_64[23] & f2_64[23];
    buff64[24] = f1_64[24] & f2_64[24];
    buff64[25] = f1_64[25] & f2_64[25];
    buff64[26] = f1_64[26] & f2_64[26];
    buff64[27] = f1_64[27] & f2_64[27];
    buff64[28] = f1_64[28] & f2_64[28];
    buff64[29] = f1_64[29] & f2_64[29];
    buff64[30] = f1_64[30] & f2_64[30];
    buff64[31] = f1_64[31] & f2_64[31];
    result += BIT_COUNT_16[buff16[64] as usize] as u32;
    result += BIT_COUNT_16[buff16[65] as usize] as u32;
    result += BIT_COUNT_16[buff16[66] as usize] as u32;
    result += BIT_COUNT_16[buff16[67] as usize] as u32;
    result += BIT_COUNT_16[buff16[68] as usize] as u32;
    result += BIT_COUNT_16[buff16[69] as usize] as u32;
    result += BIT_COUNT_16[buff16[70] as usize] as u32;
    result += BIT_COUNT_16[buff16[71] as usize] as u32;
    result += BIT_COUNT_16[buff16[72] as usize] as u32;
    result += BIT_COUNT_16[buff16[73] as usize] as u32;
    result += BIT_COUNT_16[buff16[74] as usize] as u32;
    result += BIT_COUNT_16[buff16[75] as usize] as u32;
    result += BIT_COUNT_16[buff16[76] as usize] as u32;
    result += BIT_COUNT_16[buff16[77] as usize] as u32;
    result += BIT_COUNT_16[buff16[78] as usize] as u32;
    result += BIT_COUNT_16[buff16[79] as usize] as u32;
    result += BIT_COUNT_16[buff16[80] as usize] as u32;
    result += BIT_COUNT_16[buff16[81] as usize] as u32;
    result += BIT_COUNT_16[buff16[82] as usize] as u32;
    result += BIT_COUNT_16[buff16[83] as usize] as u32;
    result += BIT_COUNT_16[buff16[84] as usize] as u32;
    result += BIT_COUNT_16[buff16[85] as usize] as u32;
    result += BIT_COUNT_16[buff16[86] as usize] as u32;
    result += BIT_COUNT_16[buff16[87] as usize] as u32;
    result += BIT_COUNT_16[buff16[88] as usize] as u32;
    result += BIT_COUNT_16[buff16[89] as usize] as u32;
    result += BIT_COUNT_16[buff16[90] as usize] as u32;
    result += BIT_COUNT_16[buff16[91] as usize] as u32;
    result += BIT_COUNT_16[buff16[92] as usize] as u32;
    result += BIT_COUNT_16[buff16[93] as usize] as u32;
    result += BIT_COUNT_16[buff16[94] as usize] as u32;
    result += BIT_COUNT_16[buff16[95] as usize] as u32;
    result += BIT_COUNT_16[buff16[96] as usize] as u32;
    result += BIT_COUNT_16[buff16[97] as usize] as u32;
    result += BIT_COUNT_16[buff16[98] as usize] as u32;
    result += BIT_COUNT_16[buff16[99] as usize] as u32;
    result += BIT_COUNT_16[buff16[100] as usize] as u32;
    result += BIT_COUNT_16[buff16[101] as usize] as u32;
    result += BIT_COUNT_16[buff16[102] as usize] as u32;
    result += BIT_COUNT_16[buff16[103] as usize] as u32;
    result += BIT_COUNT_16[buff16[104] as usize] as u32;
    result += BIT_COUNT_16[buff16[105] as usize] as u32;
    result += BIT_COUNT_16[buff16[106] as usize] as u32;
    result += BIT_COUNT_16[buff16[107] as usize] as u32;
    result += BIT_COUNT_16[buff16[108] as usize] as u32;
    result += BIT_COUNT_16[buff16[109] as usize] as u32;
    result += BIT_COUNT_16[buff16[110] as usize] as u32;
    result += BIT_COUNT_16[buff16[111] as usize] as u32;
    result += BIT_COUNT_16[buff16[112] as usize] as u32;
    result += BIT_COUNT_16[buff16[113] as usize] as u32;
    result += BIT_COUNT_16[buff16[114] as usize] as u32;
    result += BIT_COUNT_16[buff16[115] as usize] as u32;
    result += BIT_COUNT_16[buff16[116] as usize] as u32;
    result += BIT_COUNT_16[buff16[117] as usize] as u32;
    result += BIT_COUNT_16[buff16[118] as usize] as u32;
    result += BIT_COUNT_16[buff16[119] as usize] as u32;
    result += BIT_COUNT_16[buff16[120] as usize] as u32;
    result += BIT_COUNT_16[buff16[121] as usize] as u32;
    result += BIT_COUNT_16[buff16[122] as usize] as u32;
    result += BIT_COUNT_16[buff16[123] as usize] as u32;
    result += BIT_COUNT_16[buff16[124] as usize] as u32;
    result += BIT_COUNT_16[buff16[125] as usize] as u32;
    result += BIT_COUNT_16[buff16[126] as usize] as u32;
    result += BIT_COUNT_16[buff16[127] as usize] as u32;

    result
}
