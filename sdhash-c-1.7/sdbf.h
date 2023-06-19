/**
 * sdbf.h: libsdbf header file
 * author: Vassil Roussev
 */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

#ifndef __SDBF_H
#define __SDBF_H

#ifndef _MAX_ELEM_COUNT
    #ifndef _DD_BLOCK
        #define _MAX_ELEM_COUNT  160
    #else
        #define _MAX_ELEM_COUNT  192
    #endif
#endif

// Command-line related
#define DELIM_CHAR       ':'
#define DELIM_STRING     ":"
#define MAGIC_DD        "sdbf-dd"
#define MAGIC_STREAM    "sdbf"
#define MAX_MAGIC_HEADER 512
#define SDBF_VERSION     2
#define VERSION_INFO    "sdhash-1.7 by Vassil Roussev, Feb 2012"

// System parameters
#define BF_SIZE			    256
#define BINS                1000
#define ENTR_POWER		    10		
#define ENTR_SCALE		    (BINS*(1 << ENTR_POWER))
#define MAX_FILES           1000000
#define MAX_THREADS         512
#define MIN_FILE_SIZE	    512
#define MIN_ELEM_COUNT      6
#define MIN_REF_ELEM_COUNT  64
#define POP_WIN_SIZE        64
#define SD_SCORE_SCALE      0.3
#define SYNC_SIZE           16384

// Command line options
#define OPT_MAX       3
//
#define OPT_MODE	  0
#define MODE_GEN      0x01
#define MODE_COMP     0x02
#define MODE_DIR      0x04
#define MODE_PAIR	  0x08
#define MODE_FIRST	  0x10
//
#define OPT_MAP       1
#define FLAG_OFF      0x00
#define FLAG_ON       0x01

//
// Ranks based on 6x100MB benchmark: txt, html, doc, xls, pdf, jpg
//
static const uint32_t ENTR64_RANKS[] = {
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    101, 102, 106, 112, 108, 107, 103, 100, 109, 113, 128, 131, 141, 111, 146, 153, 148, 134, 145, 110,
    114, 116, 130, 124, 119, 105, 104, 118, 120, 132, 164, 180, 160, 229, 257, 211, 189, 154, 127, 115,
    129, 142, 138, 125, 136, 126, 155, 156, 172, 144, 158, 117, 203, 214, 221, 207, 201, 123, 122, 121,
    135, 140, 157, 150, 170, 387, 390, 365, 368, 341, 165, 166, 194, 174, 184, 133, 139, 137, 149, 173,
    162, 152, 159, 167, 190, 209, 238, 215, 222, 206, 205, 181, 176, 168, 147, 143, 169, 161, 249, 258,
    259, 254, 262, 217, 185, 186, 177, 183, 175, 188, 192, 195, 182, 151, 163, 199, 239, 265, 268, 242,
    204, 197, 193, 191, 218, 208, 171, 178, 241, 200, 236, 293, 301, 256, 260, 290, 240, 216, 237, 255,
    232, 233, 225, 210, 196, 179, 202, 212, 420, 429, 425, 421, 427, 250, 224, 234, 219, 230, 220, 269,
    247, 261, 235, 327, 332, 337, 342, 340, 252, 187, 223, 198, 245, 243, 263, 228, 248, 231, 275, 264,
    298, 310, 305, 309, 270, 266, 251, 244, 213, 227, 273, 284, 281, 318, 317, 267, 291, 278, 279, 303,
    452, 456, 453, 446, 450, 253, 226, 246, 271, 277, 295, 302, 299, 274, 276, 285, 292, 289, 272, 300,
    297, 286, 314, 311, 287, 283, 288, 280, 296, 304, 308, 282, 402, 404, 401, 415, 418, 313, 320, 307,
    315, 294, 306, 326, 321, 331, 336, 334, 316, 328, 322, 324, 325, 330, 329, 312, 319, 323, 352, 345,
    358, 373, 333, 346, 338, 351, 343, 405, 389, 396, 392, 411, 378, 350, 388, 407, 423, 419, 409, 395,
    353, 355, 428, 441, 449, 474, 475, 432, 457, 448, 435, 462, 470, 467, 468, 473, 426, 494, 487, 506,
    504, 517, 465, 459, 439, 472, 522, 520, 541, 540, 527, 482, 483, 476, 480, 721, 752, 751, 728, 730,
    490, 493, 495, 512, 536, 535, 515, 528, 518, 507, 513, 514, 529, 516, 498, 492, 519, 508, 544, 547,
    550, 546, 545, 511, 532, 543, 610, 612, 619, 649, 691, 561, 574, 591, 572, 553, 551, 565, 597, 593,
    580, 581, 642, 578, 573, 626, 696, 584, 585, 595, 590, 576, 579, 583, 605, 569, 560, 558, 570, 556,
    571, 656, 657, 622, 624, 631, 555, 566, 564, 562, 557, 582, 589, 603, 598, 604, 586, 577, 588, 613,
    615, 632, 658, 625, 609, 614, 592, 600, 606, 646, 660, 666, 679, 685, 640, 645, 675, 681, 672, 747,
    723, 722, 697, 686, 601, 647, 677, 741, 753, 750, 715, 707, 651, 638, 648, 662, 667, 670, 684, 674,
    693, 678, 664, 652, 663, 639, 680, 682, 698, 695, 702, 650, 676, 669, 665, 688, 687, 701, 700, 706,
    683, 718, 703, 713, 720, 716, 735, 719, 737, 726, 744, 736, 742, 740, 739, 731, 711, 725, 710, 704,
    708, 689, 729, 727, 738, 724, 733, 692, 659, 705, 654, 690, 655, 671, 628, 634, 621, 616, 630, 599,
    629, 611, 620, 607, 623, 618, 617, 635, 636, 641, 637, 633, 644, 653, 699, 694, 714, 734, 732, 746,
    749, 755, 745, 757, 756, 758, 759, 761, 763, 765, 767, 771, 773, 774, 775, 778, 782, 784, 786, 788,
    793, 794, 797, 798, 803, 804, 807, 809, 816, 818, 821, 823, 826, 828, 829, 834, 835, 839, 843, 846,
    850, 859, 868, 880, 885, 893, 898, 901, 904, 910, 911, 913, 916, 919, 922, 924, 930, 927, 931, 938,
    940, 937, 939, 941, 934, 936, 932, 933, 929, 928, 926, 925, 923, 921, 920, 918, 917, 915, 914, 912,
    909, 908, 907, 906, 900, 903, 902, 905, 896, 899, 897, 895, 891, 894, 892, 889, 883, 890, 888, 879,
    887, 886, 882, 878, 884, 877, 875, 872, 876, 870, 867, 874, 873, 871, 869, 881, 863, 865, 864, 860,
    853, 855, 852, 849, 857, 856, 862, 858, 861, 854, 851, 848, 847, 845, 844, 841, 840, 837, 836, 833,
    832, 831, 830, 827, 824, 825, 822, 820, 819, 817, 815, 812, 814, 810, 808, 806, 805, 799, 796, 795,
    790, 787, 785, 783, 781, 777, 776, 772, 770, 768, 769, 764, 762, 760, 754, 743, 717, 712, 668, 661,
    643, 627, 608, 594, 587, 568, 559, 552, 548, 542, 539, 537, 534, 533, 531, 525, 521, 510, 505, 497,
    496, 491, 486, 485, 478, 477, 466, 469, 463, 458, 460, 444, 440, 424, 433, 403, 410, 394, 393, 385,
    377, 379, 382, 383, 380, 384, 372, 370, 375, 366, 354, 363, 349, 357, 347, 364, 367, 359, 369, 360,
    374, 344, 376, 335, 371, 339, 361, 348, 356, 362, 381, 386, 391, 397, 399, 398, 412, 408, 414, 422,
    416, 430, 417, 434, 400, 436, 437, 438, 442, 443, 447, 406, 451, 413, 454, 431, 455, 445, 461, 464,
    471, 479, 481, 484, 489, 488, 499, 500, 509, 530, 523, 538, 526, 549, 554, 563, 602, 596, 673, 567,
    748, 575, 766, 709, 779, 780, 789, 813, 811, 838, 842, 866, 942, 935, 944, 943, 947, 952, 951, 955,
    954, 957, 960, 959, 967, 966, 969, 962, 968, 953, 972, 961, 982, 979, 978, 981, 980, 990, 987, 988,
    984, 983, 989, 985, 986, 977, 976, 975, 973, 974, 970, 971, 965, 964, 963, 956, 958, 524, 950, 948,
    949, 945, 946, 800, 801, 802, 791, 792, 501, 502, 503, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000 };

static const uint32_t BIT_MASKS[] = {
  0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF,
  0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF,
  0x01FFFF, 0x03FFFF, 0x07FFFF, 0x0FFFFF, 0x1FFFFF, 0x3FFFFF, 0x7FFFFF, 0xFFFFFF,
  0x01FFFFFF, 0x03FFFFFF, 0x07FFFFFF, 0x0FFFFFFF, 0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF
};

static const uint8_t BITS[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

static const uint32_t BF_CLASS_MASKS[] = { 0x7FF, 0x7FFF, 0x7FFFF, 0x7FFFFF, 0x7FFFFFF, 0xFFFFFFFF};

uint8_t bit_count_16[64*KB];

// BF digest (SDBF) description
typedef struct {
    int8_t   *name;          // Name (usually, source file)
    uint32_t  bf_count;      // Number of BFs
    uint32_t  bf_size;       // BF size in bytes (==m/8)
    uint32_t  hash_count;    // Number of hash functions used (k)
    uint32_t  mask;          // Bit mask used (must agree with m)
    uint32_t  max_elem;      // Max number of elements per filter (n)
    uint32_t  last_count;    // Actual number of elements in last filter (n_last); 
							 // ZERO means look at elem_counts value 
    uint8_t  *buffer;        // Beginning of the BF cluster
    uint16_t *hamming;	     // Hamming weight for each BF
    uint16_t *elem_counts;   // Individual elements counts for each BF (used in dd mode)
    uint32_t  dd_block_size; // Size of the base block in dd mode
} sdbf_t;

// SDHASH global parameters
typedef struct {
	uint32_t  thread_cnt;
	uint32_t  entr_win_size;
	uint32_t  bf_size;
	uint32_t  block_size;
	uint32_t  pop_win_size;
	uint32_t  threshold;
	uint32_t  max_elem;
    int32_t   output_threshold;
    uint32_t  warnings;
    uint32_t  sample_size;
} sdbf_parameters_t;

// P-threading task spesicification structure for matching SDBFs 
typedef struct {
	uint32_t  tid;			// Thread id
	uint32_t  tcount;		// Total thread count for the job
    sem_t     sem_start;    // Starting semaphore (allows thread to enter iteration)
    sem_t     sem_end;      // Ending semaphore (signals the end of an iteration)
	sdbf_t   *ref_sdbf;  	// Reference SDBF
	uint32_t  ref_index;	// Index of the reference BF
	sdbf_t   *tgt_sdbf;		// Target SDBF
	double 	  result;		// Result: max score for the task
} sdbf_task_t; 

// P-threading task specification file-parallel stream hashing 
typedef struct {
	uint32_t  tid;			// Thread id
	uint32_t  tcount;		// Total thread count for the job
    char    **filenames;    // Files to be hashed 
    uint32_t  file_count;   // Total number of files 
    uint32_t  hashed_count; // Result: total number of files actually hashed
} filehash_task_t; 

// P-threading task specification structure for block hashing 
typedef struct {
	uint32_t  tid;			// Thread id
	uint32_t  tcount;		// Total thread count for the job
    uint8_t  *buffer;       // File buffer to be hashed 
    uint64_t  file_size;    // File size (for the buffer) 
    uint64_t  block_size;   // Block size
	sdbf_t   *sdbf;		    // Result SDBF
} blockhash_task_t; 

// sdbf_api.c: Top-level API
// ------------------------- 
int   	sdbf_init(); 
void  	sdbf_finalize();
int  	sdbf_free( sdbf_t *sdbf);
sdbf_t *sdbf_hashfile( char *filename, uint32_t dd_block_size);
sdbf_t *sdbf_hash_buffer( uint8_t *buffer, uint64_t buffer_size, char *name);
int     sdbf_hash_files( char **filenames, uint32_t file_count, uint32_t gen_mode);
int     sdbf_hash_files_dd( char **filenames, uint32_t file_count, uint32_t gen_mode, uint32_t dd_block_size);
sdbf_t *sdbf_hash_dd( char *filename, uint32_t dd_block_size);

sdbf_t *sdbf_create( char *name);
int     sdbf_add( sdbf_t *sdbf);
int 	sdbf_remove( char *sdbf_name);
sdbf_t *sdbf_lookup( sdbf_t *sdbf, int threshold, int *result);
sdbf_t *sdbf_get( uint32_t index);
int     sdbf_get_size();
char   *sdbf_get_name( uint32_t index);
int     sdbf_compare( uint32_t index1, uint32_t index2, uint32_t map_on, int *swap);
char   *sdbf_encode( sdbf_t *sdbf);
sdbf_t *sdbf_decode( char *sdbf_b64);
void 	sdbf_to_stream( sdbf_t *sdbf, FILE *out);
int     sdbf_load( const char *fname);

// sdbf_core.c: Core SDBF generation/comparison functions
// ------------------------------------------------------
void 	gen_chunk_scores( const uint16_t *chunk_ranks, const uint64_t chunk_size, uint16_t *chunk_scores, int32_t *score_histo);
void gen_chunk_hash( uint8_t *file_buffer, const uint64_t chunk_pos, const uint16_t *chunk_scores, const uint64_t chunk_size, sdbf_t *sdbf);
void gen_block_hash( uint8_t *file_buffer, uint64_t file_size, const uint64_t block_num, const uint16_t *chunk_scores, const uint64_t block_size,  
                     sdbf_t *sdbf, uint32_t rem, uint32_t threshold, int32_t allowed);
sdbf_t *gen_chunk_sdbf( uint8_t *file_buffer, uint64_t file_size, uint64_t chunk_size, sdbf_t *sdbf);
sdbf_t *gen_block_sdbf( uint8_t *file_buffer, uint64_t file_size, uint64_t block_size, sdbf_t *sdbf);
sdbf_t *gen_block_sdbf_mt( uint8_t *file_buffer, uint64_t file_size, uint64_t block_size, sdbf_t *sdbf, uint32_t thread_cnt);
int     sdbf_score( sdbf_t *sd_1, sdbf_t *sd_2, uint32_t map_on, int *swap);
int     sdbf_score2( sdbf_t *sd_1, sdbf_t *sd_2, uint32_t thread_cnt);
double  sdbf_max_score( sdbf_task_t *task, uint32_t map_on);
double  sdbf_max_score2( sdbf_task_t *task);
sdbf_t *sdbf_compress( sdbf_t *base, uint8_t factor);

// entr64.c: 64-byte window functions
// --------------------------------
void     entr64_table_init_int();
uint64_t entr64_init_int( const uint8_t *buffer, uint8_t *ascii);
uint64_t entr64_inc_int( uint64_t entropy, const uint8_t *buffer, uint8_t *ascii);

// bf_utils.c: bit manipulation
// ----------------------------
void     init_bit_count_16();
int 	 compute_hamming( sdbf_t *sdbf);
uint32_t bf_bitcount( uint8_t *bfilter_1, uint8_t *bfilter_2, uint32_t bf_size);
uint32_t bf_bitcount_cut_256( uint8_t *bfilter_1, uint8_t *bfilter_2, uint32_t cut_off, int32_t slack);
uint32_t bf_sha1_insert( uint8_t *bf, uint8_t bf_class, uint32_t *sha1_hash);
uint32_t bf_match_est( uint32_t m, uint32_t k, uint32_t s1, uint32_t s2, uint32_t common);
int32_t  get_elem_count( sdbf_t *sdbf, uint64_t index);
void     bf_merge( uint32_t *base, uint32_t *overlay, uint32_t size);

// base64.c: Base64 encoding/decoding
// ----------------------------------
char     *b64encode(const char *input, int length);
char     *b64decode(char *input, int length, int *decoded_len);
uint64_t  b64decode_into( const uint8_t *input, uint64_t length, uint8_t *output);

// sdhash_opts.c: sdhash helper functions
// --------------------------------------
int     process_opts( int argc, char **argv, uint32_t *opts);
void    print_usage( char *version_info, char *command);

#endif
