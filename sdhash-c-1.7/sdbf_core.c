/**
 * sdbf_core.c: Similarity digest calculation functions. 
 * author: Vassil Roussev
 */

#include <sys/mman.h>

#include "sdbf.h"

extern sdbf_parameters_t sdbf_sys;

static uint16_t *ranks_int;
static pthread_t *thread_pool = NULL;
static sdbf_task_t *tasklist = NULL;

/**
 * Create and initialize an sdbf_t structure ready for stream mode.
 */
sdbf_t *sdbf_create( char *name) {
	sdbf_t *sdbf = (sdbf_t *)alloc_check( ALLOC_ZERO, sizeof( sdbf_t), "sdbf_create", "sdbf", ERROR_EXIT);
	sdbf->name = name;
	sdbf->bf_size = sdbf_sys.bf_size;
	sdbf->hash_count = 5;
	sdbf->mask = BF_CLASS_MASKS[0];
	sdbf->max_elem = sdbf_sys.max_elem;
    sdbf->bf_count = 1;
    return sdbf;
}

/**
 * Pre-compute Hamming weights for each BF and adds them to the SDBF descriptor.
 */ 
int compute_hamming( sdbf_t *sdbf) {
	uint32_t pos, bf_count = sdbf->bf_count;
	sdbf->hamming = (uint16_t *) alloc_check( ALLOC_ZERO, bf_count*sizeof( uint16_t), "compute_hamming", "sdbf->hamming", ERROR_EXIT);
		
	uint64_t i, j;
	uint16_t *buffer16 = (uint16_t *)sdbf->buffer;
    for( i=0,pos=0; i<bf_count; i++) {
		for( j=0; j<BF_SIZE/2; j++,pos++) {
			sdbf->hamming[i] += bit_count_16[buffer16[pos]];
		}
	}
	return 0;
}

/**
 * Generate ranks for a file chunk.
 */
void gen_chunk_ranks( uint8_t *file_buffer, const uint64_t chunk_size, uint16_t *chunk_ranks, uint16_t carryover) {
    uint64_t offset, entropy=0;
	uint8_t *ascii = (uint8_t *)alloc_check( ALLOC_ZERO, 256, "gen_chunk_ranks", "ascii", ERROR_EXIT);;

	if( carryover > 0) {
		memcpy( chunk_ranks, chunk_ranks+chunk_size-carryover, carryover*sizeof(uint16_t));
	}
	bzero( chunk_ranks+carryover, (chunk_size-carryover)*sizeof( uint16_t));
	for( offset=0; offset<chunk_size-sdbf_sys.entr_win_size; offset++) {
		// Initial/sync entropy calculation
		 if( offset % sdbf_sys.block_size == 0) {
			entropy = entr64_init_int( file_buffer+offset, ascii);
		// Incremental entropy update (much faster)
		} else {
			entropy = entr64_inc_int( entropy, file_buffer+offset-1, ascii);
		}
        chunk_ranks[offset] = ENTR64_RANKS[entropy >> ENTR_POWER];
	}
    free( ascii);
}

/**
 * Generate scores for a ranks chunk.
 */
void gen_chunk_scores( const uint16_t *chunk_ranks, const uint64_t chunk_size, uint16_t *chunk_scores, int32_t *score_histo) { 
    uint64_t i, j;
    uint32_t pop_win = sdbf_sys.pop_win_size;
    uint64_t min_pos = 0;
    uint16_t min_rank = chunk_ranks[min_pos]; 

	bzero( chunk_scores, chunk_size*sizeof( uint16_t));
    for( i=0; i<chunk_size-pop_win; i++) {
        // try sliding on the cheap    
        if( i>0 && min_rank>0) {
            while( chunk_ranks[i+pop_win] >= min_rank && i<min_pos && i<chunk_size-pop_win+1) {
                if( chunk_ranks[i+pop_win] == min_rank)
                    min_pos = i+pop_win;
                chunk_scores[min_pos]++;
                i++;
            }
        }      
        min_pos = i;
        min_rank = chunk_ranks[min_pos];
        for( j=i+1; j<i+pop_win; j++) {
            if( chunk_ranks[j] < min_rank && chunk_ranks[j]) {
                min_rank = chunk_ranks[j];
                min_pos = j;
            } else if( min_pos == j-1 && chunk_ranks[j] == min_rank) {
                min_pos = j;
            }
        }
        if( chunk_ranks[min_pos] > 0) {
            chunk_scores[min_pos]++;
        }
    }
    // Generate score histogram (for b-sdbf signatures)
    if( score_histo) {
        for( i=0; i<chunk_size-pop_win; i++)
            score_histo[chunk_scores[i]]++;
    }
}
/**
 * Generate SHA1 hashes and add them to the SDBF--original stream version.
 */
void gen_chunk_hash( uint8_t *file_buffer, const uint64_t chunk_pos, const uint16_t *chunk_scores, const uint64_t chunk_size, sdbf_t *sdbf) {
	uint64_t i;
    uint32_t sha1_hash[5];
	uint32_t bf_count = sdbf->bf_count;
	uint32_t last_count = sdbf->last_count;
	uint8_t *curr_bf = sdbf->buffer + (bf_count-1)*(sdbf->bf_size);

	for( i=0; i<chunk_size-sdbf_sys.pop_win_size; i++) {
		if( chunk_scores[i] > sdbf_sys.threshold) {
			SHA1( file_buffer+chunk_pos+i, sdbf_sys.pop_win_size, (uint8_t *)sha1_hash);
			uint32_t bits_set = bf_sha1_insert( curr_bf, 0, (uint32_t *)sha1_hash);
            // Avoid potentially repetitive features
			if( !bits_set)
				continue;
			last_count++;
			// Todo: check curr_bf for size vs. alloc_buffer
			if( last_count == sdbf_sys.max_elem) {
				curr_bf += sdbf->bf_size;
				bf_count++;
				last_count = 0;

			}
		}
	}
	sdbf->bf_count = bf_count;
	sdbf->last_count = last_count;//
}
/**
 * Generate SHA1 hashes and add them to the SDBF--block-aligned version.
 */
void gen_block_hash( uint8_t *file_buffer, uint64_t file_size, const uint64_t block_num, const uint16_t *chunk_scores, \
					 const uint64_t block_size, sdbf_t *sdbf, uint32_t rem, uint32_t threshold, int32_t allowed) {

    uint8_t  *bf = sdbf->buffer + block_num*(sdbf->bf_size);  // BF to be filled
    uint8_t  *data = file_buffer + block_num*block_size;  // Start of data
    uint32_t  i, hash_cnt=0, sha1_hash[5];
    uint32_t  max_offset = (rem > 0) ? rem : block_size;

	for( i=0; i<max_offset-sdbf_sys.pop_win_size && hash_cnt<sdbf_sys.max_elem; i++) {
		if(  chunk_scores[i] > threshold || 
            (chunk_scores[i] == threshold && allowed > 0)) {
                SHA1( data+i, sdbf_sys.pop_win_size, (uint8_t *)sha1_hash);
                uint32_t bits_set = bf_sha1_insert( bf, 0, (uint32_t *)sha1_hash);
                if( !bits_set)
                    continue;
                hash_cnt++;
                if( chunk_scores[i] == threshold) 
                    allowed--;
		}
	}
    sdbf->elem_counts[block_num] = hash_cnt; 
}

/**
 * Generate SDBF hash for a buffer--stream version.
 */
sdbf_t *gen_chunk_sdbf( uint8_t *file_buffer, uint64_t file_size, uint64_t chunk_size, sdbf_t *sdbf) {
	assert( chunk_size > sdbf_sys.pop_win_size);
    
    uint32_t i, k, sum, allowed;
    int32_t score_histo[66];  // Score histogram 
    uint64_t buff_size = ((file_size >> 11) + 1) << 8; // Estimate sdbf size (reallocate later)
    buff_size = (buff_size < 256) ? 256 : buff_size;                // Ensure min size
    sdbf->buffer = (uint8_t *)alloc_check( ALLOC_ZERO, buff_size, "gen_chunk_sdbf", "sdbf_buffer", ERROR_EXIT);

	// Chunk-based computation
	uint64_t qt = file_size/chunk_size;
	uint64_t rem = file_size % chunk_size;

	uint64_t chunk_pos = 0;
	uint16_t *chunk_ranks = (uint16_t *)alloc_check( ALLOC_ONLY, (chunk_size)*sizeof( uint16_t), "gen_chunk_sdbf", "chunk_ranks", ERROR_EXIT);
	uint16_t *chunk_scores = (uint16_t *)alloc_check( ALLOC_ZERO, (chunk_size)*sizeof( uint16_t), "gen_chunk_sdbf", "chunk_scores", ERROR_EXIT);

	for( i=0; i<qt; i++, chunk_pos+=chunk_size) {
		gen_chunk_ranks( file_buffer+chunk_size*i, chunk_size, chunk_ranks, 0);
        bzero( score_histo, sizeof( score_histo));
		gen_chunk_scores( chunk_ranks, chunk_size, chunk_scores, score_histo);

        // Calculate thresholding paremeters
        for( k=65, sum=0; k>=sdbf_sys.threshold; k--) {
            if( (sum <= sdbf_sys.max_elem) && (sum+score_histo[k] > sdbf_sys.max_elem))
                break;
            sum += score_histo[k];
        }
        allowed = sdbf_sys.max_elem-sum;
		gen_chunk_hash( file_buffer, chunk_pos, chunk_scores, chunk_size, sdbf);
	} 
	if( rem > 0) {
		gen_chunk_ranks( file_buffer+qt*chunk_size, rem, chunk_ranks, 0);
		gen_chunk_scores( chunk_ranks, rem, chunk_scores, 0);
		gen_chunk_hash( file_buffer, chunk_pos, chunk_scores, rem, sdbf);
	}

	// Chop off last BF if its membership is too low (eliminates some FPs)
	if( sdbf->bf_count > 1 && sdbf->last_count < sdbf->max_elem/8) {
		sdbf->bf_count = sdbf->bf_count-1;
		sdbf->last_count = sdbf_sys.max_elem;
	}
	// Trim BF allocation to size
	if( sdbf->bf_count*sdbf->bf_size < buff_size) {
		sdbf->buffer = realloc_check( sdbf->buffer, (sdbf->bf_count*sdbf->bf_size));
	}
	free( chunk_ranks);
	free( chunk_scores);

	return sdbf;
}
/**
 * Generate SDBF hash for a buffer--block version.
 */
sdbf_t *gen_block_sdbf( uint8_t *file_buffer, uint64_t file_size, const uint64_t block_size, sdbf_t *sdbf) {
  
    uint32_t i, k, sum, allowed;
    int32_t score_histo[66];
    
	// Block-based computation
	uint64_t qt = file_size/block_size;
	uint64_t rem = file_size % block_size;

	uint64_t chunk_pos = 0;
	uint16_t *chunk_ranks = (uint16_t *)alloc_check( ALLOC_ONLY, (block_size)*sizeof( uint16_t), "gen_block_sdbf", "chunk_ranks", ERROR_EXIT);
	uint16_t *chunk_scores = (uint16_t *)alloc_check( ALLOC_ZERO, (block_size)*sizeof( uint16_t), "gen_block_sdbf", "chunk_scores", ERROR_EXIT);

	for( i=0; i<qt; i++, chunk_pos+=block_size) {
		gen_chunk_ranks( file_buffer+block_size*i, block_size, chunk_ranks, 0);
        bzero( score_histo, sizeof( score_histo));
		gen_chunk_scores( chunk_ranks, block_size, chunk_scores, score_histo);

        // Calculate thresholding paremeters
        for( k=65, sum=0; k>=sdbf_sys.threshold; k--) {
            if( (sum <= sdbf_sys.max_elem) && (sum+score_histo[k] > sdbf_sys.max_elem))
                break;
            sum += score_histo[k];
        }
        allowed = sdbf_sys.max_elem-sum;
		gen_block_hash( file_buffer, file_size, i, chunk_scores, block_size, sdbf, 0, k, allowed);
	} 
	if( rem >= MIN_FILE_SIZE) {
		gen_chunk_ranks( file_buffer+block_size*qt, rem, chunk_ranks, 0);
		gen_chunk_scores( chunk_ranks, rem, chunk_scores, NULL);
		gen_block_hash( file_buffer, file_size, qt, chunk_scores, block_size, sdbf, rem, sdbf_sys.threshold, sdbf_sys.max_elem);     
    }
	free( chunk_ranks);
	free( chunk_scores);
	return sdbf;
}
/**
 * Worker thread for multi-threaded block hash generation.
 */
void *thread_gen_block_sdbf( void *task_param) {
    uint32_t i, k, sum, allowed;
    int32_t  score_histo[66];
    blockhash_task_t *hashtask = (blockhash_task_t *)task_param;
    uint64_t block_size = hashtask->block_size;
    uint8_t *buffer = hashtask->buffer;
    uint64_t file_size = hashtask->file_size;
    
	uint64_t qt = file_size/block_size;
	uint64_t rem = file_size % block_size;

	uint64_t chunk_pos = 0;
	uint16_t *chunk_ranks = (uint16_t *)alloc_check( ALLOC_ONLY, (block_size)*sizeof( uint16_t), "gen_block_sdbf", "chunk_ranks", ERROR_EXIT);
	uint16_t *chunk_scores = (uint16_t *)alloc_check( ALLOC_ZERO, (block_size)*sizeof( uint16_t), "gen_block_sdbf", "chunk_scores", ERROR_EXIT);

	for( i=hashtask->tid; i<qt; i+=hashtask->tcount, chunk_pos+=hashtask->tcount*block_size) {
		gen_chunk_ranks( buffer+block_size*i, block_size, chunk_ranks, 0);
        bzero( score_histo, sizeof( score_histo));
		gen_chunk_scores( chunk_ranks, block_size, chunk_scores, score_histo);
        // Calculate thresholding paremeters
        for( k=65, sum=0; k>=sdbf_sys.threshold; k--) {
            if( (sum <= sdbf_sys.max_elem) && (sum+score_histo[k] > sdbf_sys.max_elem))
                break;
            sum += score_histo[k];
        }
        allowed = sdbf_sys.max_elem-sum;
		gen_block_hash( buffer, file_size, i, chunk_scores, block_size, hashtask->sdbf, 0, k, allowed);
	} 
	free( chunk_ranks);
	free( chunk_scores);
}

sdbf_t *gen_block_sdbf_mt( uint8_t *file_buffer, uint64_t file_size, uint64_t block_size, sdbf_t *sdbf, uint32_t thread_cnt) {
    if( thread_cnt < 2)
        return gen_block_sdbf( file_buffer, file_size, block_size, sdbf);
        
    blockhash_task_t *tasks = (blockhash_task_t *) alloc_check( ALLOC_ONLY, thread_cnt*sizeof( blockhash_task_t), "gen_block_sdbf_mt", "tasks", ERROR_EXIT);
    thread_pool = (pthread_t *) alloc_check( ALLOC_ZERO, thread_cnt*sizeof( pthread_t), "gen_block_sdbf_mt", "thread_pool", ERROR_EXIT);
    int t;
    for( t=0; t<thread_cnt; t++) {
		tasks[t].tid = t;
		tasks[t].tcount = thread_cnt;
        tasks[t].buffer = file_buffer;
        tasks[t].file_size = file_size;
        tasks[t].block_size = block_size;
        tasks[t].sdbf = sdbf;
        if( pthread_create( &thread_pool[t], NULL, thread_gen_block_sdbf, (void *)(tasks+t) )) {
            fprintf( stderr, "ERROR: Could not create thread.\n");
            exit(-1);
        }
 	}
    for( t=0; t<thread_cnt; t++) {
        pthread_join( thread_pool[t], NULL);
    }
    // Deal with the "tail" if necessary
  	uint64_t qt = file_size/block_size;
	uint64_t rem = file_size % block_size;

   	if( rem >= MIN_FILE_SIZE) {
		uint16_t *chunk_ranks = (uint16_t *)alloc_check( ALLOC_ONLY, (block_size)*sizeof( uint16_t), "gen_block_sdbf_mt", "chunk_ranks", ERROR_EXIT);
        uint16_t *chunk_scores = (uint16_t *)alloc_check( ALLOC_ZERO, (block_size)*sizeof( uint16_t), "gen_block_sdbf_mt", "chunk_scores", ERROR_EXIT);

        gen_chunk_ranks( file_buffer+block_size*qt, rem, chunk_ranks, 0);
		gen_chunk_scores( chunk_ranks, rem, chunk_scores, NULL);
		gen_block_hash( file_buffer, file_size, qt, chunk_scores, block_size, sdbf, rem, sdbf_sys.threshold, sdbf_sys.max_elem);     

        free( chunk_ranks);
        free( chunk_scores);
    }
    return sdbf;
}

/**
 * Threading envelope for sdbf_max_score
 */
void *thread_sdbf_max_score( void *task_param) {
    sdbf_task_t *task = (sdbf_task_t *)task_param;
    uint32_t i;
    while( 1) {
        sem_wait( &task->sem_start);
        sdbf_max_score( (sdbf_task_t *)task, FLAG_OFF);
        sem_post( &task->sem_end);
    }
}

/**
 * Calculates the score between two digests
 */
int sdbf_score( sdbf_t *sdbf_1, sdbf_t *sdbf_2, uint32_t map_on, int *swap) {
    *swap = 0;
    double max_score, score_sum = -1;
    uint32_t i, t, thread_cnt = sdbf_sys.thread_cnt;

    if( !sdbf_1->hamming)
        compute_hamming( sdbf_1);
    if( !sdbf_2->hamming)
        compute_hamming( sdbf_2);
        
	// Make sure |sdbf_1| <<< |sdbf_2|
    if( (sdbf_1->bf_count > sdbf_2->bf_count) ||
        (sdbf_1->bf_count == sdbf_2->bf_count && 
            ((get_elem_count( sdbf_1, sdbf_1->bf_count-1) > get_elem_count( sdbf_2, sdbf_2->bf_count-1)) ||
              strcmp( sdbf_1->name, sdbf_2->name) > 0 ))) {
            sdbf_t *tmp = sdbf_1;
            sdbf_1 = sdbf_2;
            sdbf_2 = tmp;
            *swap = 1;
    }
    
    if( !tasklist)
        tasklist = (sdbf_task_t *) alloc_check( ALLOC_ZERO, thread_cnt*sizeof( sdbf_task_t), "sdbf_score", "tasklist", ERROR_EXIT);
	// Initialize common data for thread task(s)
	for( t=0; t<thread_cnt; t++) {
		tasklist[t].tid = t;
		tasklist[t].tcount = thread_cnt;
		tasklist[t].ref_sdbf = sdbf_1;
		tasklist[t].tgt_sdbf = sdbf_2;
	}
    // Create thread pool & semaphores
    if( !thread_pool && thread_cnt > 1) {
        thread_pool = (pthread_t *) alloc_check( ALLOC_ZERO, thread_cnt*sizeof( pthread_t), "sdbf_score", "thread_pool", ERROR_EXIT);
        for( t=0; t<thread_cnt; t++) {
            if( pthread_create( &thread_pool[t], NULL, thread_sdbf_max_score, (void *)(tasklist+t) )) {
                fprintf( stderr, "ERROR: Could not create thread.\n");
                exit(-1);
            }
            if( sem_init( &tasklist[t].sem_start, 0, 0) || sem_init( &tasklist[t].sem_end, 0, 0)) {
                fprintf( stderr, "ERROR: Could not create semaphores.\n");
                exit(-1);
            }
        }
    }
    for( i=0; i<sdbf_1->bf_count; i++) {
		// No threading
		if( thread_cnt < 2) {
			tasklist[0].ref_index=i;
			max_score = sdbf_max_score( tasklist, map_on);
		// === Threading ===
		} else {
            for( t=0; t<thread_cnt; t++) {
                tasklist[t].ref_index=i;
                sem_post( &(tasklist[t].sem_start));
            }
            for( t=0; t<thread_cnt; t++) {
                sem_wait( &tasklist[t].sem_end);
            }
            max_score = tasklist[0].result;
            for( t=1; t<thread_cnt; t++) {
                max_score = (tasklist[t].result > max_score) ? tasklist[t].result : max_score;
            }
		// === Done threading ===
		}
        score_sum = (score_sum < 0) ? max_score : score_sum + max_score;
        if( map_on == FLAG_ON) {
            printf( "  %5.3f\n", max_score);
        }
    }
    uint64_t denom = sdbf_1->bf_count;
    // Adjust for the case where s2 for the last BF of sdbf_2 is less then MIN_REF_ELEM_COUNT
    /*
    if( sdbf_1->bf_count > 1 && get_elem_count( sdbf_2, sdbf_2->bf_count-1) < MIN_REF_ELEM_COUNT) {
        denom--;
    }
    */
    return (score_sum < 0) ? -1 : lround( 100.0*score_sum/(denom));
}

/**
 * Given a BF and an SDBF, calculates the maximum match (0-100)
 */
double sdbf_max_score( sdbf_task_t *task, uint32_t map_on) {
	assert( task != NULL);

    double score, max_score=-1;
    uint32_t i, s1, s2, min_est, max_est, match, cut_off, slack=48;
    uint32_t bf_size = task->ref_sdbf->bf_size;
    uint16_t *bf_1, *bf_2;
	
    s1 = get_elem_count( task->ref_sdbf, task->ref_index);
	// Are there enough elements to even consider comparison?
	if( s1 < MIN_ELEM_COUNT)
		return max_score;
    bf_1 = (uint16_t *)(task->ref_sdbf->buffer + task->ref_index*bf_size);
	uint32_t e1_cnt = task->ref_sdbf->hamming[task->ref_index];
	uint32_t comp_cnt = task->tgt_sdbf->bf_count;
	for( i=task->tid; i<comp_cnt; i+=task->tcount) {
		bf_2 = (uint16_t *)(task->tgt_sdbf->buffer + i*bf_size);
        s2 = get_elem_count( task->tgt_sdbf, i);
		if( task->ref_sdbf->bf_count > 1 && s2 < MIN_REF_ELEM_COUNT)
			continue;
		uint32_t e2_cnt = task->tgt_sdbf->hamming[i];

		// Max/min number of matching bits & zero cut off
		max_est = (e1_cnt < e2_cnt) ? e1_cnt : e2_cnt;
		min_est = bf_match_est( 8*bf_size, task->ref_sdbf->hash_count, s1, s2, 0);
		cut_off = lround( SD_SCORE_SCALE*(double)(max_est-min_est)+(double)min_est);

		// Find matching bits
		match = bf_bitcount_cut_256( (uint8_t *)bf_1, (uint8_t *)bf_2, cut_off, slack);
		if( match > 0) {
			match = bf_bitcount_cut_256( (uint8_t *)bf_1, (uint8_t *)bf_2, 0, 0);
		}
		score = (match <= cut_off) ? 0 : (double)(match-cut_off)/(max_est-cut_off);
		if( map_on == FLAG_ON && sdbf_sys.thread_cnt == 1) {
			printf( "%s", (score > 0) ? "+" : ".");
		}
		max_score = (score > max_score) ? score : max_score;
	}
    task->result = max_score;
	return max_score;
}
