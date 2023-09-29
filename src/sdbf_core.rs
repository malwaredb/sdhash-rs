use crate::bf_utils::bf_sha1_insert;
use crate::entr64;
use crate::{Sdbf, ENTR64_RANKS, ENTR_POWER, SDBF_SYS};
use std::ffi::c_ushort;

use bytemuck::try_cast_slice_mut;
use sha1::digest::FixedOutput;
use sha1::{Digest, Sha1};

/// Generate ranks for a file chunk.
pub fn gen_chunk_ranks(
    file_buffer: &[u8],
    chunk_size: u64,
    chunk_ranks: &mut [u16],
    carryover: u16,
) {
    let mut entropy = 0;
    let mut ascii: entr64::Ascii = [0u8; 256];

    if carryover > 0 {
        chunk_ranks.rotate_left(carryover as usize);
    }

    chunk_ranks
        .iter_mut()
        .skip(carryover as usize)
        .for_each(|m| *m = 0);

    for offset in 0..chunk_size as usize - SDBF_SYS.entr_win_size as usize {
        // Initial/sync entropy calculation
        if offset % SDBF_SYS.block_size as usize == 0 {
            entropy = entr64::entr64_init_int(&file_buffer[offset..], &mut ascii);
        } else {
            // Incremental entropy update (much faster)
            entropy = entr64::entr64_inc_int(entropy, &file_buffer[offset - 1..], &mut ascii);
        }
        chunk_ranks[offset] = ENTR64_RANKS[(entropy >> ENTR_POWER as u64) as usize];
    }
}

/// Generate scores for a ranks chunk.
pub fn gen_chunk_scores(
    chunk_ranks: &[u16],
    chunk_size: u64,
    chunk_scores: &mut [u16],
    score_histo: Option<&mut [i32]>,
) {
    let pop_win = SDBF_SYS.pop_win_size as u64;
    let mut min_pos = 0u64;
    let mut min_rank = chunk_ranks[min_pos as usize];

    chunk_scores.iter_mut().for_each(|m| *m = 0);

    for mut i in 0..chunk_size - pop_win {
        // try sliding on the cheap
        if i > 0 && min_rank > 0 {
            while chunk_ranks[(i + pop_win) as usize] >= min_rank
                && i < min_pos
                && i < chunk_size - pop_win + 1
            {
                if chunk_ranks[(i + pop_win) as usize] == min_rank {
                    min_pos = i + pop_win;
                }
                chunk_scores[min_pos as usize] += 1;
                i += 1;
            }
        }
        min_pos = i;
        min_rank = chunk_ranks[min_pos as usize];

        for j in i + 1..pop_win {
            if chunk_ranks[j as usize] < min_rank && chunk_ranks[j as usize] > 0 {
                min_rank = chunk_ranks[j as usize];
                min_pos = j;
            } else if min_pos == j - 1 && chunk_ranks[j as usize] == min_rank {
                min_pos = j;
            }
        }
        if chunk_ranks[min_pos as usize] > 0 {
            chunk_scores[min_pos as usize] += 1;
        }
    }

    // Generate score histogram (for b-sdbf signatures)
    if let Some(score_histo) = score_histo {
        for i in 0..chunk_size - pop_win {
            score_histo[chunk_scores[i as usize] as usize] += 1;
        }
    }
}

/// Generate SHA1 hashes and add them to the SDBF--original stream version.
pub fn gen_chunk_hash(
    file_buffer: &[u8],
    chunk_pos: u64,
    chunk_scores: &[u16],
    chunk_size: u64,
    sdbf: &mut Sdbf,
) {
    let mut bf_count = sdbf.bf_count;
    let mut last_count = sdbf.last_count;
    let mut curr_bf = &mut sdbf.buffer[(bf_count as usize - 1)..];

    for i in 0..chunk_size - SDBF_SYS.pop_win_size as u64 {
        if chunk_scores[i as usize] > SDBF_SYS.threshold {
            let mut sha1 = Sha1::new();
            sha1.update(&file_buffer[(chunk_pos + i) as usize..]);
            let result = sha1.finalize_fixed();
            let mut result = result.as_slice().to_vec();
            let mut sha1 = try_cast_slice_mut::<u8, u32>(&mut result)
                .expect("gen_chunk_hash(): failed to SHA-1 hash bytes to &[u32]");
            let bits_set = bf_sha1_insert(curr_bf, 0, sha1);
            if bits_set == 0 {
                continue;
            }
            last_count += 1;
            // Todo: check curr_bf for size vs. alloc_buffer
            if last_count == SDBF_SYS.max_elem {
                curr_bf = &mut curr_bf[sdbf.bf_size as usize..];
                bf_count += 1;
                last_count = 0;
            }
        }
    }

    sdbf.bf_count = bf_count;
    sdbf.last_count = last_count;
}

/// Generate SHA1 hashes and add them to the SDBF--block-aligned version.
#[allow(clippy::too_many_arguments)]
pub fn gen_block_hash(
    file_buffer: &[u8],
    file_size: u64,
    block_num: u64,
    chunk_scores: &[u16],
    block_size: u64,
    sdbf: &mut Sdbf,
    rem: u32,
    threshold: u32,
    allowed: i32,
) {
    let mut hash_cnt = 0;
    let mut allowed = allowed;
    let mut bf = &mut sdbf.buffer[(block_num * sdbf.bf_size as u64) as usize..]; // BF to be filled
    let mut data = &file_buffer[(block_num * block_size) as usize..]; // Start of data

    let max_offset = if rem > 0 { rem as u64 } else { block_size };

    for i in 0..(max_offset - SDBF_SYS.pop_win_size as u64) as usize {
        if chunk_scores[i] as u32 > threshold || chunk_scores[i] as u32 == threshold && allowed > 0
        {
            let mut sha1 = Sha1::new();
            sha1.update(&file_buffer[i..]);
            let result = sha1.finalize_fixed();
            let mut result = result.as_slice().to_vec();
            let mut sha1 = try_cast_slice_mut::<u8, u32>(&mut result)
                .expect("gen_chunk_hash(): failed to SHA-1 hash bytes to &[u32]");
            let bits_set = bf_sha1_insert(bf, 0, sha1);
            if bits_set == 0 {
                continue;
            }
            hash_cnt += 1;
            if chunk_scores[i] as u32 == threshold {
                allowed -= 1;
            }
        }
    }
    sdbf.elem_counts[block_num as usize] = hash_cnt;
}

/// Generate SDBF hash for a buffer--stream version.
pub fn gen_chunk_sdbf(file_buffer: &[u8], file_size: u64, chunk_size: u64, sdbf: &mut Sdbf) {
    debug_assert!(
        chunk_size > SDBF_SYS.pop_win_size as u64,
        "Chunk size {} should be greater than SDBF_SYS.pop_win_size {}",
        chunk_size,
        SDBF_SYS.pop_win_size
    );

    let mut sum = 0;
    let mut allowed = 0;
    //uint32_t i, k, sum, allowed;
    let mut score_histo = [0i32; 66]; // Score histogram
    let buff_size = ((file_size >> 11) + 1) << 8; // Estimate sdbf size (reallocate later)
    let buff_size = buff_size.max(256); // Ensure min size
    sdbf.buffer = Vec::new();
    sdbf.buffer.resize(buff_size as usize, 0);

    // Chunk-based computation
    let qt = file_size / chunk_size;
    let rem = file_size % chunk_size;

    let mut chunk_pos = 0;
    let mut chunk_ranks: Vec<u16> = Vec::new();
    let mut chunk_scores: Vec<u16> = Vec::new();
    chunk_ranks.resize(chunk_size as usize, 0);
    chunk_scores.resize(chunk_size as usize, 0);
    // uint16_t *chunk_ranks = (uint16_t *)alloc_check( ALLOC_ONLY, (chunk_size)*sizeof( uint16_t), "gen_chunk_sdbf", "chunk_ranks", ERROR_EXIT);
    // uint16_t *chunk_scores = (uint16_t *)alloc_check( ALLOC_ZERO, (chunk_size)*sizeof( uint16_t), "gen_chunk_sdbf", "chunk_scores", ERROR_EXIT);

    for i in 0..qt {
        gen_chunk_ranks(
            &file_buffer[(chunk_size * i) as usize..],
            chunk_size,
            &mut chunk_ranks,
            0,
        );

        score_histo.iter_mut().for_each(|m| *m = 0);
        gen_chunk_scores(
            &chunk_ranks,
            chunk_size,
            &mut chunk_scores,
            Some(&mut score_histo),
        );

        // Calculate thresholding paremeters
        #[allow(clippy::needless_range_loop)]
        for k in 65..=SDBF_SYS.threshold as usize {
            if sum <= SDBF_SYS.max_elem && sum + score_histo[k] as u32 > SDBF_SYS.max_elem {
                break;
            }
            sum += score_histo[k] as u32;
        }

        allowed = SDBF_SYS.max_elem - sum;
        gen_chunk_hash(file_buffer, chunk_pos, &chunk_scores, chunk_size, sdbf);
        chunk_pos += chunk_size;
    }

    if rem > 0 {
        gen_chunk_ranks(
            &file_buffer[(qt * chunk_size) as usize..],
            rem,
            &mut chunk_ranks,
            0,
        );
        gen_chunk_scores(&chunk_ranks, rem, &mut chunk_scores, None);
        gen_chunk_hash(file_buffer, chunk_pos, &chunk_scores, rem, sdbf);
    }

    // Chop off last BF if its membership is too low (eliminates some FPs)
    if sdbf.bf_count > 1 && sdbf.last_count < sdbf.max_elem / 8 {
        sdbf.bf_count -= 1;
        sdbf.last_count = SDBF_SYS.max_elem;
    }
    // Trim BF allocation to size
    if ((sdbf.bf_count * sdbf.bf_size) as u64) < buff_size {
        sdbf.buffer = sdbf.buffer[..(sdbf.bf_count * sdbf.bf_size) as usize].to_owned();
        //sdbf.buffer = realloc_check( sdbf->buffer, (sdbf->bf_count*sdbf->bf_size));
    }
}

/// Generate SDBF hash for a buffer--block version.
pub fn gen_block_sdbf(file_buffer: &[u8], file_size: u64, block_size: u64, sdbf: &mut Sdbf) {
    let mut sum = 0;
    let mut allowed = 0i32;

    let mut score_histo = [0i32; 66]; // Score histogram

    // Block-based computation
    let qt = file_size / block_size;
    let rem = file_size % block_size;

    let mut chunk_pos = 0u64;
    let mut chunk_ranks: Vec<u16> = Vec::new();
    let mut chunk_scores: Vec<u16> = Vec::new();
    chunk_ranks.resize(block_size as usize, 0);
    chunk_scores.resize(block_size as usize, 0);
    //uint16_t *chunk_ranks = (uint16_t *)alloc_check( ALLOC_ONLY, (block_size)*sizeof( uint16_t), "gen_block_sdbf", "chunk_ranks", ERROR_EXIT);
    //uint16_t *chunk_scores = (uint16_t *)alloc_check( ALLOC_ZERO, (block_size)*sizeof( uint16_t), "gen_block_sdbf", "chunk_scores", ERROR_EXIT);

    for i in 0..qt {
        gen_chunk_ranks(
            &file_buffer[(block_size * i) as usize..],
            block_size,
            &mut chunk_ranks,
            0,
        );
        score_histo.iter_mut().for_each(|m| *m = 0);
        gen_chunk_scores(
            &chunk_ranks,
            block_size,
            &mut chunk_scores,
            Some(&mut score_histo),
        );

        // Calculate thresholding paremeters
        let mut k = 65;
        loop {
            if sum <= SDBF_SYS.max_elem && sum as i32 + score_histo[k] > SDBF_SYS.max_elem as i32 {
                break;
            }
            sum += score_histo[k] as u32;
            k -= 1;
            if k <= SDBF_SYS.threshold as usize {
                break;
            }
        }
        allowed = (SDBF_SYS.max_elem - sum) as i32;
        gen_block_hash(
            file_buffer,
            file_size,
            i,
            &chunk_scores,
            block_size,
            sdbf,
            0,
            k as u32,
            allowed,
        );

        chunk_pos += block_size
    }

    if rem >= crate::MIN_FILE_SIZE as u64 {
        gen_chunk_ranks(
            &file_buffer[(block_size * qt) as usize..],
            rem,
            &mut chunk_ranks,
            0,
        );
        gen_chunk_scores(&chunk_ranks, rem, &mut chunk_scores, None);
        gen_block_hash(
            file_buffer,
            file_size,
            qt,
            &chunk_scores,
            block_size,
            sdbf,
            rem as u32,
            SDBF_SYS.threshold as u32,
            SDBF_SYS.max_elem as i32,
        );
    }
}
