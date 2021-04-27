#ifndef HEADER_SM4_H
#define HEADER_SM4_H
#include <stdint.h>

#define SM4_KEY_SIZE            16
#define SM4_BLOCK_SIZE          16
#define SM4_NUM_ROUNDS          32

typedef struct {
        uint8_t nonce[4];
        uint8_t iv[8];
        uint8_t ctr[4];
} rfc3686_blk;

struct sm4_key {
	unsigned int rk[SM4_NUM_ROUNDS];
};

struct sm4_ctx {
	struct sm4_key key;
	rfc3686_blk blk;	
};


void sm4_encrypt_ctr(char *dst, int len, char *in_key);
#define sm4_decrypt_ctr sm4_encrypt_ctr
#endif
