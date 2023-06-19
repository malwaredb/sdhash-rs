/**
 * sdhash_api.c: sdhash API
 * author: Vassil Roussev
 */

#include "sdbf.h"

// Global parameters
extern sdbf_parameters_t sdbf_sys;

// State
static sdbf_t **sdbf_list = NULL;
static uint32_t curr_sdbf = 0;
static pthread_mutex_t set_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Initialization of SDBF structures. Must be called once before the remaining sdbf functions are used.
 */
int sdbf_init() {
	sdbf_list = (sdbf_t **)alloc_check( ALLOC_ZERO, (MAX_FILES*sizeof( sdbf_t **)), "sdbf_init", "sdbf_list", ERROR_EXIT);
    entr64_table_init_int();
	init_bit_count_16();
	return 0;
}

/**
 * Frees up SDBF structures. 
 */
void sdbf_finalize() {
	if( sdbf_list)
		free( sdbf_list);
}

/**
 * Add a digest to a collection. Returns number of digests in collection.
 * Todo: sdbf_add() --> reimplement
 */
int sdbf_add( sdbf_t *sdbf) {
	assert( sdbf_list && curr_sdbf < MAX_FILES);

    pthread_mutex_lock( &set_mutex);	
        sdbf_list[curr_sdbf] = sdbf;
        curr_sdbf++;
    pthread_mutex_unlock( &set_mutex);	
	return curr_sdbf;
}

/**
 * Remove a digest to a collection. Returns number of digests in collection.
 * Todo: sdbf_remove() --> reimplement 
 */
int sdbf_remove( char *sdbf_name) {
	assert( sdbf_name != NULL);
	
	uint32_t i, j, len = strlen( sdbf_name);
    pthread_mutex_lock( &set_mutex);	
	for( i=0; i<curr_sdbf; i++) {
		if( strncmp( sdbf_name, sdbf_list[i]->name, len) == 0) {
			sdbf_free( sdbf_list[i]);
			for( j=i; j<curr_sdbf-1; j++)
				sdbf_list[j] = sdbf_list[j+1];
			curr_sdbf--;
			break;
		}
	}
    pthread_mutex_unlock( &set_mutex);	
	return curr_sdbf;
}

/**
 * Look up a digest. Returns the first match above the threshold.
 */
sdbf_t *sdbf_lookup( sdbf_t *query, int threshold, int *result) {
	if( query->hamming == NULL)
		compute_hamming( query);
	int i, score, *swap;
	for( i=0; i<curr_sdbf; i++)
		score = sdbf_score( query, sdbf_list[i], FLAG_OFF, swap);
		if( score >= threshold) {
			*result = score;
			return sdbf_list[i];
		}
	return NULL;
}

/**
 * Returns the number digests.
 */
int sdbf_get_size() {
	return curr_sdbf;
}

/**
 * Returns the SDBF associated with an index
 */
sdbf_t *sdbf_get( uint32_t index) {
	if( index < curr_sdbf)
		return sdbf_list[index];
	else
		return NULL;
}

/**
 * Returns the name (string) associates with an SDBF
 */
char *sdbf_get_name( uint32_t index) {
	if( index < curr_sdbf)
		return sdbf_list[index]->name;
	else
		return NULL;
}

/**
 * Compares digests by index.
 */
int sdbf_compare( uint32_t index1, uint32_t index2, uint32_t map_on, int *swap) {
	assert( index1 < curr_sdbf && index2 < curr_sdbf);
	
    return sdbf_score( sdbf_list[index1], sdbf_list[index2], map_on, swap);
}

/**
 * Releases an SDBF structure.
 */
int sdbf_free( sdbf_t *sdbf) {
	if( sdbf) {
        if( sdbf->buffer)
            free( sdbf->buffer);
        if( sdbf->hamming)
            free( sdbf->hamming);
        if( sdbf->elem_counts)
            free( sdbf->elem_counts);
		free( sdbf);
		return 0;
	}
	return -1;
}

/**
 * Compute SD for a file.
 */
sdbf_t *sdbf_hashfile( char *filename, uint32_t dd_block_size) {
    mapped_file_t *mfile = mmap_file( filename, MIN_FILE_SIZE, sdbf_sys.warnings);
    if( !mfile)
        return NULL;
    sdbf_t *sdbf = sdbf_create( filename);
    if( !sdbf)
        return NULL;

    // Stream-mode fork
    if( !dd_block_size) {
        gen_chunk_sdbf( mfile->buffer, mfile->size, 32*MB, sdbf);	
    // Block-mode fork
    } else {
        uint64_t dd_block_cnt =  mfile->size/dd_block_size;
        if( mfile->size % dd_block_size >= MIN_FILE_SIZE)
            dd_block_cnt++;
        sdbf->bf_count = dd_block_cnt;
        sdbf->dd_block_size = dd_block_size;
        sdbf->buffer = (uint8_t *)alloc_check( ALLOC_ZERO, dd_block_cnt*sdbf_sys.bf_size, "sdbf_hash_dd", "sdbf->buffer", ERROR_EXIT);
        sdbf->elem_counts = (uint16_t *)alloc_check( ALLOC_ZERO, sizeof( uint16_t)*dd_block_cnt, "sdbf_hash_dd", "sdbf->elem_counts", ERROR_EXIT);
        gen_block_sdbf_mt( mfile->buffer, mfile->size, dd_block_size, sdbf, sdbf_sys.thread_cnt);	
    }  
	munmap( mfile->buffer, mfile->size);
    fclose( mfile->input);
	return sdbf;
}

/**
 * Compute stream SD for a (presumably small) memory buffer.
 */
sdbf_t *sdbf_hash_buffer( uint8_t *buffer, uint64_t buffer_size, char *name) {
    sdbf_t *sdbf = sdbf_create( name);
    if( !sdbf)
        return NULL;
    gen_chunk_sdbf( buffer, buffer_size, 32*MB, sdbf);	
	return sdbf;
}

/**
 * Threading envelope for sdbf_hashfile
 */
void *thread_sdbf_hashfile( void *task_param) {
    filehash_task_t *task = (filehash_task_t *)task_param;

    int i;
    for( i=task->tid; i<task->file_count; i+=task->tcount) {
        sdbf_t *sdbf = sdbf_hashfile( task->filenames[i], 0);
        if( sdbf) {
            sdbf_add( sdbf);
            task->hashed_count++;
        }
    }
}

/**
 * Compute block-based SD for a file.
 */
sdbf_t *sdbf_hash_dd( char *filename, uint32_t dd_block_size) {
    mapped_file_t *mfile = mmap_file( filename, MIN_FILE_SIZE, sdbf_sys.warnings);
    if( !mfile) {
        return NULL;
    }
    // Calculate total number of blocks
    uint64_t dd_block_cnt =  mfile->size/dd_block_size;
    if( mfile->size % dd_block_size >= MIN_FILE_SIZE)
       dd_block_cnt++;

	sdbf_t *sdbf = (sdbf_t *)alloc_check( ALLOC_ZERO, sizeof( sdbf_t), "sdbf_hash_dd", "sdbf", ERROR_EXIT);
	sdbf->name = filename;
	sdbf->bf_size = sdbf_sys.bf_size;
	sdbf->hash_count = 5;
	sdbf->mask = BF_CLASS_MASKS[0];
	sdbf->max_elem = sdbf_sys.max_elem;

	sdbf->bf_count = dd_block_cnt;
    sdbf->dd_block_size = dd_block_size;
	sdbf->buffer = (uint8_t *)alloc_check( ALLOC_ZERO, dd_block_cnt*sdbf_sys.bf_size, "sdbf_hash_dd", "sdbf->buffer", ERROR_EXIT);
	sdbf->elem_counts = (uint16_t *)alloc_check( ALLOC_ZERO, sizeof( uint16_t)*dd_block_cnt, "sdbf_hash_dd", "sdbf->elem_counts", ERROR_EXIT);

	gen_block_sdbf_mt( mfile->buffer, mfile->size, dd_block_size, sdbf, sdbf_sys.thread_cnt);	

	munmap( mfile->buffer, mfile->size);
    fclose( mfile->input);
	return sdbf;
}
/**
 * Compute SD for a list of files & add them to the set.
 */
int sdbf_hash_files( char **filenames, uint32_t file_count, uint32_t gen_mode) {
    int32_t i, t, result = 0, thread_cnt = sdbf_sys.thread_cnt;

    // Sequential implementation
    if( thread_cnt == 1) {
        for( i=0; i<file_count; i++) {
            sdbf_t *sdbf = sdbf_hashfile( filenames[i], 0);
            if( sdbf) {
                if( gen_mode == MODE_GEN) {
                    sdbf_to_stream( sdbf, stdout);
                    sdbf_free( sdbf);
                } else
                    sdbf_add( sdbf);
                result++;
            }
        }
    // Threaded implementation
    } else {
        pthread_t *thread_pool = (pthread_t *) alloc_check( ALLOC_ZERO, thread_cnt*sizeof( pthread_t), "sdbf_hash_files", "thread_pool", ERROR_EXIT);
        filehash_task_t *tasks = (filehash_task_t *) alloc_check( ALLOC_ZERO, thread_cnt*sizeof( filehash_task_t), "sdbf_hash_files", "tasks", ERROR_EXIT);
        for( t=0; t<thread_cnt; t++) {
            tasks[t].tid = t;
            tasks[t].tcount = thread_cnt;
            tasks[t].filenames = filenames;
            tasks[t].file_count = file_count;
            if( pthread_create( &thread_pool[t], NULL, thread_sdbf_hashfile, (void *)(tasks+t) )) {
                fprintf( stderr, "ERROR: Could not create thread.\n");
                exit(-1);
            }
        }
        for( t=0; t<thread_cnt; t++) {
            pthread_join( thread_pool[t], NULL);
            result += tasks[t].hashed_count;
        }
    // End threading
    }
    if( gen_mode == MODE_GEN) {
        for( i=0; i<sdbf_get_size(); i++)
            sdbf_to_stream( sdbf_get( i), stdout);
    }
	return result;
}


/**
 * Compute block-based SD for a list of files & add them to the set.
 */
int sdbf_hash_files_dd( char **filenames, uint32_t file_count, uint32_t gen_mode, uint32_t dd_block_size) {
    int32_t i, result = 0;

    for( i=0; i<file_count; i++) {
        sdbf_t *sdbf = sdbf_hash_dd( filenames[i], dd_block_size);
        if( sdbf) {
            if( gen_mode == MODE_GEN) {
                sdbf_to_stream( sdbf, stdout);
                sdbf_free( sdbf);
            } else
				sdbf_add( sdbf);
            result++;
        }
    }
	return result;
}

/**
 * Base64 encoding of SDBF; top-level interface
 */
char *sdbf_encode( sdbf_t *sdbf) {
	char header[64*KB], *base64, *base64_buffer;
	sprintf( header, "%s sdbf:sha1:%d:%d:%x:%d:%d:%d:",  sdbf->name, sdbf->bf_size, sdbf->hash_count, sdbf->mask, 
														 sdbf->max_elem, sdbf->bf_count, sdbf->last_count);
	base64 = (char *)alloc_check( ALLOC_ZERO, (strlen( header)+(sdbf->bf_size)*(sdbf->bf_count)*8/6 + 4), "sdbf_encode", "base64", ERROR_EXIT);
	if( !base64)
		return NULL;
	base64_buffer = b64encode( (char *)(sdbf->buffer), (sdbf->bf_size)*(sdbf->bf_count));
	sprintf( base64, "%s%s", header, base64_buffer);
	free( base64_buffer);
	return base64;
}

/**
 * Base64 encoding of SDBF; top-level interface
 */
void sdbf_to_stream( sdbf_t *sdbf, FILE *out) {
    // Stream version
    if( !sdbf->elem_counts) {
        fprintf( out, "%s:%02d:%d:%s:sha1:%d:%d:%x:%d:%d:%d:", MAGIC_STREAM, SDBF_VERSION, (int)strlen( sdbf->name), sdbf->name, sdbf->bf_size, 
                                                            sdbf->hash_count, sdbf->mask, sdbf->max_elem, sdbf->bf_count, sdbf->last_count);
        uint64_t qt = sdbf->bf_count/6, rem = sdbf->bf_count % 6;
        uint64_t i, pos=0, b64_block = 6*sdbf->bf_size;

        for( i=0,pos=0; i<qt; i++,pos+=b64_block) {
            char *b64 = b64encode( sdbf->buffer + pos, b64_block);
            fprintf( out, "%s", b64);
            free( b64);
        }
        if( rem>0) {
            char *b64 = b64encode( sdbf->buffer + pos, rem*sdbf->bf_size);          
            fprintf( out, "%s", b64);
            free( b64);
        }
    // Block version
    } else {
        fprintf( out,  "%s:%02d:%d:%s:sha1:%d:%d:%x:%d:%d:%d", MAGIC_DD, SDBF_VERSION, (int)strlen( sdbf->name), sdbf->name, sdbf->bf_size, 
                                                               sdbf->hash_count, sdbf->mask, sdbf->max_elem, sdbf->bf_count, sdbf->dd_block_size);
        int i;
        for( i=0; i<sdbf->bf_count; i++) {
            char *b64 = b64encode( sdbf->buffer+i*sdbf->bf_size, sdbf->bf_size);
            fprintf( out, ":%02X:%s", sdbf->elem_counts[i], b64);
        }
    }
    fprintf( out, "\n");
}

sdbf_t *sdbf_from_stream( FILE *in) {
    char *b64, fmt[64];
    uint8_t  buffer[16*KB], sdbf_magic[16], hash_magic[8];
    uint32_t colon_cnt, read_cnt, hash_cnt, d_len, b64_len;
    uint32_t version, name_len;
    uint64_t i;

    for( i=0, colon_cnt=3; i<MAX_MAGIC_HEADER && !feof(in); i++) {
        buffer[i] = fgetc( in);
        if( buffer[i] == DELIM_CHAR) {
            buffer[i] = 0x20;
            colon_cnt--;
            if( !colon_cnt)
                break;
        }
    }
    if( feof( in))
        return NULL;
    buffer[i] = 0;
    sscanf( buffer, "%s %d %d", &(sdbf_magic[0]), &version, &name_len);
    if( (strcmp( sdbf_magic, MAGIC_STREAM) && strcmp( sdbf_magic, MAGIC_DD)) || version != 2) {
        fprintf( stderr, "ERROR: Unsupported format '%s:%02d'. Expecting '%s:02' or '%s:02'\n", sdbf_magic, version, MAGIC_STREAM, MAGIC_DD);
        exit(-1);
    }
	sdbf_t *sdbf = (sdbf_t *)alloc_check( ALLOC_ZERO, sizeof( sdbf_t), "sdbf_from_stream", "sdbf", ERROR_EXIT);
    fmt[0] = '%';
    sprintf( fmt+1, "%dc", name_len);
    sdbf->name = (uint8_t *)alloc_check( ALLOC_ZERO, name_len+2, "sdbf_from_stream", "sdbf->name", ERROR_EXIT);
    read_cnt = fscanf( in, fmt, sdbf->name);

    read_cnt = fscanf( in, ":%4s:%d:%d:%x:%d:%d", hash_magic, &(sdbf->bf_size), &(sdbf->hash_count), &(sdbf->mask), &(sdbf->max_elem), &(sdbf->bf_count));
    sdbf->buffer = (uint8_t *)alloc_check( ALLOC_ZERO, sdbf->bf_count*sdbf->bf_size, "sdbf_from_stream", "sdbf->buffer", ERROR_EXIT);
    // DD fork
    if( !strcmp( sdbf_magic, MAGIC_DD)) {
        read_cnt = fscanf( in, ":%d", &(sdbf->dd_block_size));
        sdbf->elem_counts = (uint16_t *)alloc_check( ALLOC_ZERO, sdbf->bf_count*sizeof(uint16_t), "sdbf_from_stream", "sdbf->elem_counts", ERROR_EXIT);
        for( i=0; i<sdbf->bf_count; i++) {
            read_cnt = fscanf( in, ":%2x:%344s", &hash_cnt, buffer);
            sdbf->elem_counts[i] = (uint16_t)hash_cnt;
            d_len = b64decode_into( buffer, 344, sdbf->buffer + i*sdbf->bf_size);
            if( d_len != 256) {
                fprintf( stderr, "ERROR: Unexpected decoded length for BF: %d. Name: %s, BF#: %d\n", d_len, sdbf->name, (int)i);
                exit(-1);
            }
        }
    // Stream fork
    } else {
        read_cnt = fscanf( in, ":%d:", &(sdbf->last_count));
        b64_len = sdbf->bf_count*sdbf->bf_size;
        b64_len = 4*(b64_len + 1 + b64_len % 3)/3;
        sprintf( &fmt[1], "%ds", b64_len);
        b64 = alloc_check( ALLOC_ZERO, b64_len+2, "sdbf_from_stream", "b64", ERROR_EXIT);
        read_cnt = fscanf( in, fmt, b64);
        sdbf->buffer = b64decode( b64, b64_len, &d_len);
        if( d_len != sdbf->bf_count*sdbf->bf_size) {
            fprintf( stderr, "ERROR: Incorrect base64 decoding length. Expected: %d, actual: %d\n", sdbf->bf_count*sdbf->bf_size, d_len);
            exit(-1);
        }
        free( b64);
    }
    return sdbf;
}

/**
 * Base64 decoding of a SDBF; top-level interface
 */
sdbf_t *sdbf_decode( char *sdbf_b64) {
	sdbf_t *sdbf = (sdbf_t *)alloc_check( ALLOC_ZERO, sizeof( sdbf_t), "sdbf_decode", "sdbf", ERROR_EXIT);

	uint32_t i, colon_cnt, name_len=0, bf_len=0, decoded_len;
	for( i=0, colon_cnt=8; colon_cnt; i++) {
		if( sdbf_b64[i] == ':') {
			if( colon_cnt == 8) {
				name_len = i+1;
			}
			colon_cnt--;
		}
	}
	sdbf->name = (char *)alloc_check( ALLOC_ZERO, name_len+2, "sdbf_decode", "sdbf->name", ERROR_EXIT);
	sscanf( sdbf_b64, "%s:sdbf:sha1:%d:%d:%x:%d:%d:%d:", sdbf->name, &(sdbf->bf_size), &(sdbf->hash_count), &(sdbf->mask), 
													    &(sdbf->max_elem), &(sdbf->bf_count), &(sdbf->last_count));
	bf_len = strlen( sdbf_b64+i);
	sdbf->buffer = b64decode( sdbf_b64+i, bf_len, &decoded_len);
	return sdbf;
}

/**
 * Base64 decoding of SDBF file; top-level interface
 */
int sdbf_load( const char *fname) {
	int sdbf_count=0;

	FILE *in = fopen( fname, "r");
    
    while( !feof( in)) {
        sdbf_t *sdbf = sdbf_from_stream( in);
        if( sdbf) {
            sdbf_add( sdbf);
            sdbf_count++;
            getc( in);
        }
	}
	return sdbf_count;
}
