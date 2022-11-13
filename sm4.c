#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "sm4.h" 

#define be32_to_cpu(n) ((((n)&0x000000ff)<<24) | (((n)&0x0000ff00)<<8) \
                        | (((n)&0x00ff0000)>>8) | (((n)&0xff000000)>>24))

#define cpu_to_be32(n) ((((n)&0x000000ff)<<24) | (((n)&0x0000ff00)<<8) \
                        | (((n)&0x00ff0000)>>8) | (((n)&0xff000000)>>24))

static rfc3686_blk ctr = {
	{0x00, 0x1C, 0xC5, 0xB7},                         /* nonce   */
	{0x51, 0xA5, 0x1D, 0x70, 0xA1, 0xC1, 0x11, 0x48}, /* IV      */
	{0x00, 0x00, 0x00, 0x01}  /* counter */
};

static const unsigned char SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

static const unsigned int  FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

static const unsigned int CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

#define ROT32(x, i)					\
	(((x) << i) | ((x) >> (32-i)))

#define L32(x)						\
	((x) ^						\
	ROT32((x),  2) ^				\
	ROT32((x), 10) ^				\
	ROT32((x), 18) ^				\
	ROT32((x), 24))

#define GET32(pc)  (					\
	((unsigned int)(pc)[0] << 24) ^				\
	((unsigned int)(pc)[1] << 16) ^				\
	((unsigned int)(pc)[2] <<  8) ^				\
	((unsigned int)(pc)[3]))

#define PUT32(st, ct)					\
	do {                                            \
		(ct)[0] = (unsigned char)((st) >> 24);		\
		(ct)[1] = (unsigned char)((st) >> 16);		\
		(ct)[2] = (unsigned char)((st) >>  8);		\
		(ct)[3] = (unsigned char)(st);			\
	} while (0)

#define S32(A)						\
	((SBOX[((A) >> 24)] << 24) ^			\
	 (SBOX[((A) >> 16) & 0xff] << 16) ^		\
	 (SBOX[((A) >>  8) & 0xff] <<  8) ^		\
	 (SBOX[((A))       & 0xff]))

#define L32_(x)						\
	((x) ^						\
	ROT32((x), 13) ^				\
	ROT32((x), 23))

#define ROUND(x0, x1, x2, x3, x4, i)			\
	do {                                            \
		x4 = x1 ^ x2 ^ x3 ^ *(rk + i);		\
		x4 = S32(x4);				\
		x4 = x0 ^ L32(x4);                      \
	} while (0)

#define ENC_KEY_ROUND(x0, x1, x2, x3, x4, i)	\
	do {                                    \
		x4 = x1 ^ x2 ^ x3 ^ *(CK + i);	\
		x4 = S32(x4);			\
		x4 = x0 ^ L32_(x4);		\
		*(rk + i) = x4;                 \
	} while (0)

#define DEC_KEY_ROUND(x0, x1, x2, x3, x4, i)	\
	do {                                    \
		x4 = x1 ^ x2 ^ x3 ^ *(CK + i);	\
		x4 = S32(x4);			\
		x4 = x0 ^ L32_(x4);		\
		*(rk + 31 - i) = x4;            \
	} while (0)

#define ROUNDS(MODE, x0, x1, x2, x3, x4)	\
	do {                                    \
		MODE(x0, x1, x2, x3, x4, 0);	\
		MODE(x1, x2, x3, x4, x0, 1);	\
		MODE(x2, x3, x4, x0, x1, 2);	\
		MODE(x3, x4, x0, x1, x2, 3);	\
		MODE(x4, x0, x1, x2, x3, 4);	\
		MODE(x0, x1, x2, x3, x4, 5);	\
		MODE(x1, x2, x3, x4, x0, 6);	\
		MODE(x2, x3, x4, x0, x1, 7);	\
		MODE(x3, x4, x0, x1, x2, 8);	\
		MODE(x4, x0, x1, x2, x3, 9);	\
		MODE(x0, x1, x2, x3, x4, 10);	\
		MODE(x1, x2, x3, x4, x0, 11);	\
		MODE(x2, x3, x4, x0, x1, 12);	\
		MODE(x3, x4, x0, x1, x2, 13);	\
		MODE(x4, x0, x1, x2, x3, 14);	\
		MODE(x0, x1, x2, x3, x4, 15);	\
		MODE(x1, x2, x3, x4, x0, 16);	\
		MODE(x2, x3, x4, x0, x1, 17);	\
		MODE(x3, x4, x0, x1, x2, 18);	\
		MODE(x4, x0, x1, x2, x3, 19);	\
		MODE(x0, x1, x2, x3, x4, 20);	\
		MODE(x1, x2, x3, x4, x0, 21);	\
		MODE(x2, x3, x4, x0, x1, 22);	\
		MODE(x3, x4, x0, x1, x2, 23);	\
		MODE(x4, x0, x1, x2, x3, 24);	\
		MODE(x0, x1, x2, x3, x4, 25);	\
		MODE(x1, x2, x3, x4, x0, 26);	\
		MODE(x2, x3, x4, x0, x1, 27);	\
		MODE(x3, x4, x0, x1, x2, 28);	\
		MODE(x4, x0, x1, x2, x3, 29);	\
		MODE(x0, x1, x2, x3, x4, 30);	\
		MODE(x1, x2, x3, x4, x0, 31);   \
	} while (0)

static void sm4_encrypt_init(struct sm4_ctx *ctx, const unsigned char *in_key, rfc3686_blk *blk)
{
	unsigned int *rk = ctx->key.rk;
	unsigned int x0, x1, x2, x3, x4;

	x0 = GET32(in_key) ^ FK[0];
	x1 = GET32(in_key  + 4) ^ FK[1];
	x2 = GET32(in_key  + 8) ^ FK[2];
	x3 = GET32(in_key + 12) ^ FK[3];

	ROUNDS(ENC_KEY_ROUND, x0, x1, x2, x3, x4);

	memcpy(&ctx->blk, blk, sizeof(*blk));
}

static void sm4_process(const struct sm4_ctx *ctx, unsigned char *out, const unsigned char *in)
{
	const unsigned int *rk = ctx->key.rk;
	unsigned int x0, x1, x2, x3, x4;

	x0 = GET32(in);
	x1 = GET32(in +  4);
	x2 = GET32(in +  8);
	x3 = GET32(in + 12);

	ROUNDS(ROUND, x0, x1, x2, x3, x4);

	PUT32(x0, out);
	PUT32(x4, out +  4);
	PUT32(x3, out +  8);
	PUT32(x2, out + 12);
}

static inline void crypto_inc_byte(unsigned char *a, unsigned int size)
{
        unsigned char *b = (a + size);
        unsigned c;

        for (; size; size--) {
                c = *--b + 1;
                *b = c;
                if (c)
                        break;
        }
}

static inline void ctr_inc_ctr(uint8_t *val, unsigned int size )
{
        unsigned int  *b = (unsigned int *)(val + size);
        unsigned c;
        unsigned d;

        for (; size >= 4; size -= 4) {
		d = *--b;
                c = be32_to_cpu(d) + 1;
                *b = cpu_to_be32(c);
                if (c)
                        return;
        }

        crypto_inc_byte(val, size);
}

static void sm4_process_ctr(struct sm4_ctx *ctx, char *buf, int len)
{
	uint8_t key[sizeof(ctx->blk)];
	size_t  i;
	uint8_t j = sizeof(key);

	for (i = 0; i < len; i++) {
		if (j == sizeof(key)) {
			j = 0;
			sm4_process(ctx, (char *)key, (char *) &ctx->blk);
			ctr_inc_ctr(&ctx->blk.ctr[0], sizeof(ctx->blk.ctr));
		}
		buf[i] ^= key[j++];
	}
}

void sm4_encrypt_ctr(char *dst, int len, char *in_key)
{
	struct sm4_ctx ctx; 
	char key[SM4_KEY_SIZE] = {0};

	strncpy(key, in_key, sizeof(key));

	sm4_encrypt_init(&ctx, key, &ctr);
	sm4_process_ctr(&ctx, dst, len);
}

