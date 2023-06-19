#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "util.h"

int fileno(FILE *stream);  // This should not be necessary but w/o it a warning is shown.

/**
 * Open & memory-map a file (compile w/ -D_FILE_OFFSET_BITS=64)
 */
mapped_file_t *mmap_file( char *fname, int64_t min_file_size, uint32_t warnings) {
    mapped_file_t *mfile = (mapped_file_t *) alloc_check( ALLOC_ZERO, sizeof( mapped_file_t), "map_file", "mfile", ERROR_EXIT);
	struct stat file_stat;

	if( !( mfile->input = fopen( fname, "r"))) {
        if( warnings)
            fprintf( stderr, "Warning: Could not open file '%s'. Skipping.\n", fname);
		return NULL;
	}
	mfile->fd = fileno( mfile->input);
	if( fstat( mfile->fd, &file_stat)) {
        if( warnings)
            fprintf( stderr, "Warning: Could not stat file '%s'. Skipping.\n", fname);
		return NULL;
	}
    if( !S_ISREG( file_stat.st_mode)) {
		if( warnings)
            fprintf( stderr, "Warning: '%s' is not a regular file. Skipping.\n", fname);
		return NULL;
    }
    if( file_stat.st_size < min_file_size) {
        if( warnings)
            fprintf( stderr, "Warning: File '%s' too small (%ld). Skipping.\n", fname, file_stat.st_size);
		return NULL;
	}
	mfile->buffer = mmap( 0, file_stat.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, mfile->fd, 0);
	if( mfile->buffer == MAP_FAILED) {
        fprintf( stderr, "mmap() failed: %s.\n", strerror( errno));
        free( mfile);
		return NULL;
	}
    mfile->name = fname;
	mfile->size = file_stat.st_size;
	return mfile;
}
