/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common values for AES algorithms
 */

#ifndef _CRYPTO_AES_H
#define _CRYPTO_AES_H
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "ctr.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int  u32;

#define AES_MIN_KEY_SIZE	16
#define AES_MAX_KEY_SIZE	32
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32
#define AES_BLOCK_SIZE		16
#define AES_MAX_KEYLENGTH	(15 * 16)
#define AES_MAX_KEYLENGTH_U32	(AES_MAX_KEYLENGTH / sizeof(u32))

#define get_unaligned_le32(p) (*(u32*)(p))
#define put_unaligned_le32(val, p) (*(u32*)(p) = (val))

#define ____cacheline_aligned __attribute__((aligned)) 
//#define __always_inline  inline

/*
 * Please ensure that the first two fields are 16-byte aligned
 * relative to the start of the structure, i.e., don't move them!
 */
struct crypto_aes_ctx {
	u32 key_enc[AES_MAX_KEYLENGTH_U32];
	u32 key_dec[AES_MAX_KEYLENGTH_U32];
	u32 key_length;
};

struct aes_ctx {
	struct crypto_aes_ctx ctx;
	rfc3686_blk blk;	
};

/*
 * validate key length for AES algorithms
 */
static inline int aes_check_keylen(unsigned int keylen)
{
	switch (keylen) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
	case AES_KEYSIZE_256:
		break;
	default:
		return -1;
	}

	return 0;
}

int aes_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
		unsigned int key_len);

/**
 * aes_expandkey - Expands the AES key as described in FIPS-197
 * @ctx:	The location where the computed key will be stored.
 * @in_key:	The supplied key.
 * @key_len:	The length of the supplied key.
 *
 * Returns 0 on success. The function fails only if an invalid key size (or
 * pointer) is supplied.
 * The expanded key size is 240 bytes (max of 14 rounds with a unique 16 bytes
 * key schedule plus a 16 bytes key which is used before the first round).
 * The decryption key is prepared for the "Equivalent Inverse Cipher" as
 * described in FIPS-197. The first slot (16 bytes) of each key (enc or dec) is
 * for the initial combination, the second slot for the first round and so on.
 */
int aes_expandkey(struct crypto_aes_ctx *ctx, const u8 *in_key,
		  unsigned int key_len);

/**
 * aes_encrypt - Encrypt a single AES block
 * @ctx:	Context struct containing the key schedule
 * @out:	Buffer to store the ciphertext
 * @in:		Buffer containing the plaintext
 */
void aes_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);

/**
 * aes_decrypt - Decrypt a single AES block
 * @ctx:	Context struct containing the key schedule
 * @out:	Buffer to store the plaintext
 * @in:		Buffer containing the ciphertext
 */
void aes_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);


int crypto_aes_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
		unsigned int key_len);
void crypto_aes_encrypt(struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
void crypto_aes_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);

void aes_encrypt_ctr(char *dst, int len, char *in_key);
#define aes_decrypt_ctr(dst, len, in_key) aes_encrypt_ctr(dst, len, in_key)

#endif
