/**
 * sdhash: Command-line interface for file hashing
 * author: Vassil Roussev
 */

#include "sdbf.h"

// Global parameters
sdbf_parameters_t sdbf_sys = {
    1,               // threads
    64,              // entr_win_size
    256,             // BF size
    4*KB,            // block_size
    64,              // pop_win_size
    16,              // threshold
    _MAX_ELEM_COUNT, // max_elem
    1,               // output_threshold
    FLAG_OFF,        // warnings
    0 		     // sample size off
};

int main( int argc, char **argv) {
    uint32_t  i, j, k, file_cnt;
    uint32_t opts[OPT_MAX];
    uint32_t first_size, all_size;
    sdbf_t* tmp;
    
    bzero( opts, OPT_MAX*sizeof( uint32_t));
    int file_start = process_opts( argc, argv, &opts[0]);
    
    if( argc < 2 || file_start < 1) {
        print_usage( VERSION_INFO, argv[0]);
        return -1;
    }
    // Initialization
    if( sdbf_init() < 0)
        return -1;
    file_cnt = argc-file_start;

    
    // Generate SDBFs from source files
    if( opts[OPT_MODE] & MODE_GEN) {
#ifdef _DD_BLOCK
        sdbf_hash_files_dd( argv+file_start, file_cnt, opts[OPT_MODE], _DD_BLOCK*KB);
#else
        sdbf_hash_files( argv+file_start, file_cnt, opts[OPT_MODE]);
#endif
    // Load SDBFs from a file
    } else if( opts[OPT_MODE] & MODE_COMP) {
           struct stat stat_res;
        if( stat( argv[file_start], &stat_res) != 0) {
            fprintf( stderr, "ERROR: Could not open SDBF file \"%s\". Exiting.\n", argv[file_start]);
            return -1;
        }
        if( sdbf_load( argv[file_start]) < 0) {
            fprintf( stderr, "ERROR: Could not load SDBF file \"%s\". Exiting.\n", argv[file_start]);
            return -1;
        }
    } else {
        fprintf( stderr, "ERROR: Inconsistent command line options: load and generate\n");
        exit( -1);
    }
    int score, swap;
    // Perform pairs comparison
    if( opts[OPT_MODE] & MODE_PAIR) {
        for( j=1; j<sdbf_get_size(); j++) {
            score = sdbf_compare( 0, j, opts[OPT_MAP], &swap);
            if( score >= sdbf_sys.output_threshold) {
                if( swap)
                    printf( "%s|%s|%03d\n", sdbf_get_name(j), sdbf_get_name(0), score);
                else
                    printf( "%s|%s|%03d\n", sdbf_get_name(0), sdbf_get_name(j), score);
            }
        }
    // Perform all-pairs comparison
    } else if( opts[OPT_MODE] & MODE_DIR) {
        for( k=0; k<sdbf_get_size()-1; k++) {
            for( j=k+1; j<sdbf_get_size(); j++) {
                score = sdbf_compare( k, j, opts[OPT_MAP], &swap);
                if( score >= sdbf_sys.output_threshold) {
                    if( swap)
                        printf( "%s|%s|%03d\n", sdbf_get_name(j), sdbf_get_name(k), score);
                    else
                        printf( "%s|%s|%03d\n", sdbf_get_name(k), sdbf_get_name(j), score);
                }
            }
        }
    // perform first file against second file comparison.  need to extend to "all files" 
    } else if (opts[OPT_MODE] & MODE_FIRST) {
        first_size=sdbf_get_size();	
	if (sdbf_load(argv[file_start+1]) < 0) {
            fprintf( stderr, "ERROR: Could not load SDBF file \"%s\". Exiting.\n", argv[file_start+1]);
            return -1;
        }
	all_size=sdbf_get_size();	
         /* sampling for -c option only for now */
	if (sdbf_sys.sample_size > 0)  {
	    for (k=0;k<first_size-1;k++) {
	       tmp=sdbf_get(k);
	       if (tmp->bf_count > sdbf_sys.sample_size) 
		    tmp->bf_count = sdbf_sys.sample_size;
	    }
	}
	if (all_size == first_size+1) {
		// we have a (single) hash target.  
	    j=first_size;
	    for (k=0;k<first_size-1;k++) {
		score = sdbf_compare( k, j, opts[OPT_MAP], &swap);
		if( score >= sdbf_sys.output_threshold) {
		    if( swap)
			printf( "%s|%s|%03d\n", sdbf_get_name(j), sdbf_get_name(k), score);
		    else
			printf( "%s|%s|%03d\n", sdbf_get_name(k), sdbf_get_name(j), score);
		}
	    }
	// we have a multi-hash target   
	} else {
	    for( k=0; k<first_size-1; k++) {
		for( j=first_size; j<all_size-1; j++) {
		    score = sdbf_compare( k, j, opts[OPT_MAP], &swap);
		    if( score >= sdbf_sys.output_threshold) {
			if( swap)
			    printf( "%s|%s|%03d\n", sdbf_get_name(j), sdbf_get_name(k), score);
			else
			    printf( "%s|%s|%03d\n", sdbf_get_name(k), sdbf_get_name(j), score);
		    }
		}
	    }
	}
    }
    sdbf_finalize();
    return 0;
}
