#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "util.h"

/**
 * Base64 encodes a memory buffer. Result is NULL terminated
 */
char *b64encode(const char *input, int length) {
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new( BIO_f_base64());
	BIO_set_flags( b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new( BIO_s_mem());
	b64 = BIO_push( b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buffer = (char *)alloc_check( ALLOC_ONLY, bptr->length+1, "b64encode", "buffer", ERROR_EXIT);
	if( !buffer)	
		return NULL;
	memcpy( buffer, bptr->data, bptr->length);
	buffer[bptr->length] = 0;
	BIO_free_all(b64);

	return buffer;
}

/**
 * Base64 decodes a memory buffer
 */
char *b64decode(char *input, int length, int *decoded_len) {
	BIO *b64, *bmem;

	char *buffer = (char *)alloc_check( ALLOC_ZERO, length, "b64decode", "buffer", ERROR_EXIT);
	if( !buffer)
		return NULL;

	b64 = BIO_new( BIO_f_base64());
	bmem = BIO_new_mem_buf( input, length);
	bmem = BIO_push( b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	*decoded_len = BIO_read( bmem, buffer, length);
	
	BIO_free_all(bmem);
	return buffer;
}
/**
 * Base64 decodes a memory buffer
 */
uint64_t b64decode_into( const uint8_t *input, uint64_t length, uint8_t *output) {
	BIO *b64, *bmem;

	b64 = BIO_new( BIO_f_base64());
	bmem = BIO_new_mem_buf( (void *)input, length);
	bmem = BIO_push( b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	uint64_t decoded_len = BIO_read( bmem, output, length);
	
	BIO_free_all(bmem);
	return decoded_len;
}
