#include "sdbf.h"

// Global parameters
extern sdbf_parameters_t sdbf_sys;

/* 
 * Process command-line options:
 */
int process_opts( int argc, char **argv, uint32_t *opts) {
    uint32_t i, opt_cnt=0;
    char opt;

    while( (opt = getopt (argc, argv, ":cgmwp:t:s:")) != -1) {
        switch( opt) {
            case 'c':
                opts[OPT_MODE] |= MODE_COMP;
//                opts[OPT_MODE] |= MODE_DIR;
                break;
            case 'g':
                opts[OPT_MODE] |= MODE_GEN;
                opts[OPT_MODE] |= MODE_DIR;
                break;
            case 'm':
                opts[OPT_MAP] = FLAG_ON;
                break;
            case 'w':
                sdbf_sys.warnings = FLAG_ON;
                break;
            case 'p':
                sdbf_sys.thread_cnt = atoi( optarg);
                break;
            case 't':
                sdbf_sys.output_threshold = atoi( optarg);
                break;
            case 's':
                sdbf_sys.sample_size = atoi( optarg);
                break;
            case ':':
                fprintf( stderr, ">>> ERROR: Missing parameter for option -%c.\n", optopt);
                return -1;
                break;
            default:
                return -1;
		}
    }
    if( !(opts[OPT_MODE] & MODE_COMP) && !(opts[OPT_MODE] & MODE_GEN)) {
		opts[OPT_MODE] = MODE_GEN;
	}
    if( (opts[OPT_MODE] & MODE_COMP) && (opts[OPT_MODE] & MODE_GEN)) {
		fprintf( stderr, ">>> ERROR: Incompatible options: 'c' and 'g'\n");
		return -1;
	}
    if( sdbf_sys.thread_cnt < 1 || sdbf_sys.thread_cnt > MAX_THREADS) {
		fprintf( stderr, ">>> ERROR: Parallelization parameter must be between 1 and %d.\n", MAX_THREADS);
		return -1;
	}
    if( sdbf_sys.output_threshold < 0 || sdbf_sys.output_threshold > 100) {
        fprintf( stderr, "Error: invalid output threshhold (%d); resetting to 1.\n", sdbf_sys.output_threshold);
        sdbf_sys.output_threshold = 1;
    }
    // to trigger -c 2 files option, if the optind is < argc and & MODE_COMP is set we have 2 files
    if (opts[OPT_MODE] & MODE_COMP)  {
	    if  (optind+2==argc) {
		opts[OPT_MODE] |= MODE_FIRST;
	    } else {
		opts[OPT_MODE] |= MODE_DIR; 
	    }
    }
    return optind;
}

/*
 *  Show usage instructions
 */
void print_usage( char *version_info, char *command) {
    printf( "%s\n", version_info);
    printf( "  sdhash <files>         : 'gen' mode: generate base64-encoded SDBFs for files to stdout.\n");
    printf( "     -g <files>          : 'all-gen' mode: generate hashes and compare all pairs.\n");
    printf( "     -c <sdbf-file>      : 'all-comp' mode: load hashes from file and compare all pairs.\n");
    printf( "     -c <query> <target> : 'query': searches for <query>.sdbf in <target>.sdbf\n");
    printf( "     -p <number>         : 'parallelization factor': run the computation at the given concurrency factor.\n");
    printf( "     -t <0-100>          : 'threshold': only show results greater than or equal to parameter; default is 1.\n");
    printf( "     -s <1-16>           : 'sample': for -c comparisons, use N or fewer filters to match; default is off.\n");
    printf( "     -m                  : 'map' comparisons: show a heat map of BF matches (requires -g or -c and no parallelism).\n");
    printf( "     -w                  : 'warnings': turn on warnings (default is OFF).\n");
}


