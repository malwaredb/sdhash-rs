/**
 * bf_utils.c: Bloom filter utilities
 * author: Vassil Roussev
 */

#include <math.h>
#include "sdbf.h"

// Global parameters
extern sdbf_parameters_t sdbf_sys;

// Makeshift cache
static uint16_t bf_est_cache[256][256];

/** 
 * Precalculates the number of set bits for all 16-bit numbers
 */
void init_bit_count_16() {
    uint32_t byte, bit;
    bzero( bit_count_16, 64*KB);
    for( byte=0; byte<64*KB; byte++) {
        for( bit=0; bit<16; bit++) {
            if( byte & 0x1 << bit)
                bit_count_16[byte]++;
        }
    }
    bzero( bf_est_cache, sizeof( bf_est_cache));
}

/**
 * Estimate number of expected matching bits
 */
uint32_t bf_match_est( uint32_t m, uint32_t k, uint32_t s1, uint32_t s2, uint32_t common) {

	// This cache should work >99% of the time
	if( !common && bf_est_cache[s1][s2]) {
		return bf_est_cache[s1][s2];
	}
	double ex = 1-1.0/m;
	uint32_t result = round((double)m*(1 - pow( ex, k*s1) - pow( ex, k*s2) + pow( ex, k*(s1+s2-common))));
	bf_est_cache[s1][s2] = (uint16_t)result;
		
	return result;
}

/**
 * Insert a SHA1 hash into a Bloom filter
 */
uint32_t bf_sha1_insert( uint8_t *bf, uint8_t bf_class, uint32_t *sha1_hash) {
    uint32_t i, k, insert_cnt = 0, bit_mask = BF_CLASS_MASKS[bf_class];
    for( i=0; i<5; i++) {
        sha1_hash[i] &= bit_mask;
        k = sha1_hash[i] >> 3;
        if( !(bf[k] & BITS[sha1_hash[i] & 0x7]))
            insert_cnt++;
        bf[k] |= BITS[sha1_hash[i] & 0x7];
    }
    return insert_cnt;
}

/**
 * bf_merge(): Performs bitwise OR on two BFs
 */
void bf_merge( uint32_t *base, uint32_t *overlay, uint32_t size) {
	int i;
	for( i=0; i<size; i++)
		base[i] |= overlay[i];
}

/**
 * Compute the number of common bits b/w two filters
 * todo: make it work with any size BF
 */
uint32_t bf_bitcount( uint8_t *bfilter_1, uint8_t *bfilter_2, uint32_t bf_size) {
    uint32_t i, result=0;
	uint64_t buff64[32];
	uint64_t *f1_64 = (uint64_t *)bfilter_1;
	uint64_t *f2_64 = (uint64_t *)bfilter_2;
	uint16_t *buff16 = (uint16_t *)buff64;
	for( i=0; i<bf_size/8; i++)
		buff64[i] = f1_64[i] & f2_64[i];

    for( i=0; i<bf_size/2; i++) {
		result += bit_count_16[buff16[i]];
	}
    return result;
   
}

/**
 * Returns the number of elements in BF (handles both sequential & dd case).
 */
int32_t get_elem_count( sdbf_t *sdbf, uint64_t index) {
    if( !sdbf->elem_counts) {
        return (index < sdbf->bf_count-1) ? sdbf->max_elem : sdbf->last_count; 
    // DD fork
    } else {
        return sdbf->elem_counts[index];
    }
}

/**
 * Computer the number of common bits (dot product) b/w two filters--conditional optimized version for 256-byte BFs.
 * The conditional looks first at the dot product of the first 32/64/128 bytes; if it is less than the threshold,
 * it returns 0; otherwise, proceeds with the rest of the computation.
 */
uint32_t bf_bitcount_cut_256( uint8_t *bfilter_1, uint8_t *bfilter_2, uint32_t cut_off, int32_t slack) {
	uint32_t result=0;
	uint64_t buff64[32];
	uint64_t *f1_64 = (uint64_t *)bfilter_1;
	uint64_t *f2_64 = (uint64_t *)bfilter_2;
	uint16_t *buff16 = (uint16_t *)buff64;

	// Partial computation (1/8 of full computation):
	buff64[0]= f1_64[0] & f2_64[0];
	buff64[1]= f1_64[1] & f2_64[1];
	buff64[2]= f1_64[2] & f2_64[2];
	buff64[3]= f1_64[3] & f2_64[3];
	result += bit_count_16[buff16[0]];
	result += bit_count_16[buff16[1]];
	result += bit_count_16[buff16[2]];
	result += bit_count_16[buff16[3]];
	result += bit_count_16[buff16[4]];
	result += bit_count_16[buff16[5]];
	result += bit_count_16[buff16[6]];
	result += bit_count_16[buff16[7]];
	result += bit_count_16[buff16[8]];
	result += bit_count_16[buff16[9]];
	result += bit_count_16[buff16[10]];
	result += bit_count_16[buff16[11]];
	result += bit_count_16[buff16[12]];
	result += bit_count_16[buff16[13]];
	result += bit_count_16[buff16[14]];
	result += bit_count_16[buff16[15]];

	// First shortcircuit for the computation
	if( cut_off > 0 && (8*result + slack) < cut_off) {
		return 0;
	}
	buff64[4]= f1_64[4] & f2_64[4];
	buff64[5]= f1_64[5] & f2_64[5];
	buff64[6]= f1_64[6] & f2_64[6];
	buff64[7]= f1_64[7] & f2_64[7];
	result += bit_count_16[buff16[16]];
	result += bit_count_16[buff16[17]];
	result += bit_count_16[buff16[18]];
	result += bit_count_16[buff16[19]];
	result += bit_count_16[buff16[20]];
	result += bit_count_16[buff16[21]];
	result += bit_count_16[buff16[22]];
	result += bit_count_16[buff16[23]];
	result += bit_count_16[buff16[24]];
	result += bit_count_16[buff16[25]];
	result += bit_count_16[buff16[26]];
	result += bit_count_16[buff16[27]];
	result += bit_count_16[buff16[28]];
	result += bit_count_16[buff16[29]];
	result += bit_count_16[buff16[30]];
	result += bit_count_16[buff16[31]];

	// Second shortcircuit for the computation
	if( cut_off > 0 && (4*result + slack) < cut_off) {
		return 0;
	}
	buff64[8]= f1_64[8] & f2_64[8];
	buff64[9]= f1_64[9] & f2_64[9];
	buff64[10]= f1_64[10] & f2_64[10];
	buff64[11]= f1_64[11] & f2_64[11];
	buff64[12]= f1_64[12] & f2_64[12];
	buff64[13]= f1_64[13] & f2_64[13];
	buff64[14]= f1_64[14] & f2_64[14];
	buff64[15]= f1_64[15] & f2_64[15];
	result += bit_count_16[buff16[32]];
	result += bit_count_16[buff16[33]];
	result += bit_count_16[buff16[34]];
	result += bit_count_16[buff16[35]];
	result += bit_count_16[buff16[36]];
	result += bit_count_16[buff16[37]];
	result += bit_count_16[buff16[38]];
	result += bit_count_16[buff16[39]];
	result += bit_count_16[buff16[40]];
	result += bit_count_16[buff16[41]];
	result += bit_count_16[buff16[42]];
	result += bit_count_16[buff16[43]];
	result += bit_count_16[buff16[44]];
	result += bit_count_16[buff16[45]];
	result += bit_count_16[buff16[46]];
	result += bit_count_16[buff16[47]];
	result += bit_count_16[buff16[48]];
	result += bit_count_16[buff16[49]];
	result += bit_count_16[buff16[50]];
	result += bit_count_16[buff16[51]];
	result += bit_count_16[buff16[52]];
	result += bit_count_16[buff16[53]];
	result += bit_count_16[buff16[54]];
	result += bit_count_16[buff16[55]];
	result += bit_count_16[buff16[56]];
	result += bit_count_16[buff16[57]];
	result += bit_count_16[buff16[58]];
	result += bit_count_16[buff16[59]];
	result += bit_count_16[buff16[60]];
	result += bit_count_16[buff16[61]];
	result += bit_count_16[buff16[62]];
	result += bit_count_16[buff16[63]];

	// Third shortcircuit for the computation
	if( cut_off > 0 && (2*result + slack) < cut_off) {
		return 0;
	}
	buff64[16]= f1_64[16] & f2_64[16];
	buff64[17]= f1_64[17] & f2_64[17];
	buff64[18]= f1_64[18] & f2_64[18];
	buff64[19]= f1_64[19] & f2_64[19];
	buff64[20]= f1_64[20] & f2_64[20];
	buff64[21]= f1_64[21] & f2_64[21];
	buff64[22]= f1_64[22] & f2_64[22];
	buff64[23]= f1_64[23] & f2_64[23];
	buff64[24]= f1_64[24] & f2_64[24];
	buff64[25]= f1_64[25] & f2_64[25];
	buff64[26]= f1_64[26] & f2_64[26];
	buff64[27]= f1_64[27] & f2_64[27];
	buff64[28]= f1_64[28] & f2_64[28];
	buff64[29]= f1_64[29] & f2_64[29];
	buff64[30]= f1_64[30] & f2_64[30];
	buff64[31]= f1_64[31] & f2_64[31];
	result += bit_count_16[buff16[64]];
	result += bit_count_16[buff16[65]];
	result += bit_count_16[buff16[66]];
	result += bit_count_16[buff16[67]];
	result += bit_count_16[buff16[68]];
	result += bit_count_16[buff16[69]];
	result += bit_count_16[buff16[70]];
	result += bit_count_16[buff16[71]];
	result += bit_count_16[buff16[72]];
	result += bit_count_16[buff16[73]];
	result += bit_count_16[buff16[74]];
	result += bit_count_16[buff16[75]];
	result += bit_count_16[buff16[76]];
	result += bit_count_16[buff16[77]];
	result += bit_count_16[buff16[78]];
	result += bit_count_16[buff16[79]];
	result += bit_count_16[buff16[80]];
	result += bit_count_16[buff16[81]];
	result += bit_count_16[buff16[82]];
	result += bit_count_16[buff16[83]];
	result += bit_count_16[buff16[84]];
	result += bit_count_16[buff16[85]];
	result += bit_count_16[buff16[86]];
	result += bit_count_16[buff16[87]];
	result += bit_count_16[buff16[88]];
	result += bit_count_16[buff16[89]];
	result += bit_count_16[buff16[90]];
	result += bit_count_16[buff16[91]];
	result += bit_count_16[buff16[92]];
	result += bit_count_16[buff16[93]];
	result += bit_count_16[buff16[94]];
	result += bit_count_16[buff16[95]];
	result += bit_count_16[buff16[96]];
	result += bit_count_16[buff16[97]];
	result += bit_count_16[buff16[98]];
	result += bit_count_16[buff16[99]];
	result += bit_count_16[buff16[100]];
	result += bit_count_16[buff16[101]];
	result += bit_count_16[buff16[102]];
	result += bit_count_16[buff16[103]];
	result += bit_count_16[buff16[104]];
	result += bit_count_16[buff16[105]];
	result += bit_count_16[buff16[106]];
	result += bit_count_16[buff16[107]];
	result += bit_count_16[buff16[108]];
	result += bit_count_16[buff16[109]];
	result += bit_count_16[buff16[110]];
	result += bit_count_16[buff16[111]];
	result += bit_count_16[buff16[112]];
	result += bit_count_16[buff16[113]];
	result += bit_count_16[buff16[114]];
	result += bit_count_16[buff16[115]];
	result += bit_count_16[buff16[116]];
	result += bit_count_16[buff16[117]];
	result += bit_count_16[buff16[118]];
	result += bit_count_16[buff16[119]];
	result += bit_count_16[buff16[120]];
	result += bit_count_16[buff16[121]];
	result += bit_count_16[buff16[122]];
	result += bit_count_16[buff16[123]];
	result += bit_count_16[buff16[124]];
	result += bit_count_16[buff16[125]];
	result += bit_count_16[buff16[126]];
	result += bit_count_16[buff16[127]];
    return result;
}




