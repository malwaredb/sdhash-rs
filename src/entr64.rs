use lazy_static::lazy_static;

pub type Ascii = [u8; 256];

lazy_static! {
    /// Entropy lookup table setup--int64 version (to be called once)
    static ref ENTROPY_64_INT: [u64; 65] = {
        let mut entropy_64_int = [0u64; 65];
        for (i, val) in entropy_64_int.iter_mut().enumerate() {
            let p = i as f64 / 64.0;
            let p = (-p * (p.log(10.0) / 2.0f64.log(10.0)) / 6.0) * crate::ENTR_SCALE as f64;
            *val = p as u64;
        }
        entropy_64_int
    };
}

#[inline]
pub fn clear_ascii(ascii: &mut Ascii) {
    ascii.iter_mut().for_each(|m| *m = 0)
}

/// Baseline entropy computation for a 64-byte buffer--int64 version (to be called periodically)
pub fn entr64_init_int(buffer: &[u8], ascii: &mut Ascii) -> u64 {
    clear_ascii(ascii);

    for i in 0..64 {
        ascii[buffer[i] as usize] += 1;
    }

    let mut entr = 0;
    for i in 0..256 {
        if ascii[i] > 0 {
            entr += ENTROPY_64_INT[ascii[i] as usize];
        }
    }

    entr
}

/// Incremental (rolling) update to entropy computation--int64 version
pub fn entr64_inc_int(prev_entropy: u64, buffer: &[u8], ascii: &mut Ascii) -> u64 {
    if buffer[0] == buffer[64] {
        return prev_entropy;
    }

    let old_char_cnt = ascii[buffer[0] as usize] as u32;
    let new_char_cnt = ascii[buffer[64] as usize] as u32;

    ascii[buffer[0] as usize] -= 1;
    ascii[buffer[64] as usize] += 1;

    if old_char_cnt == new_char_cnt + 1 {
        return prev_entropy;
    }

    let old_diff =
        (ENTROPY_64_INT[old_char_cnt as usize] - ENTROPY_64_INT[old_char_cnt as usize - 1]) as i64;
    let new_diff =
        (ENTROPY_64_INT[new_char_cnt as usize + 1] - ENTROPY_64_INT[new_char_cnt as usize]) as i64;

    let mut entropy = prev_entropy as i64 - old_diff + new_diff;
    if entropy < 0 {
        entropy = 0;
    } else if entropy > crate::ENTR_SCALE as i64 {
        entropy = crate::ENTR_SCALE as i64;
    }

    entropy as u64
}
