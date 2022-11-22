#ifndef HEADER_CTR_H
#define HEADER_CTR_H
#include <stdint.h>

typedef struct {
        uint8_t nonce[4];
        uint8_t iv[8];
        uint8_t ctr[4];
} rfc3686_blk;

#endif
