#ifndef _HIDE_PROC_HEADER_CTR_H
#define _HODE_PROC_HEADER_CTR_H
#include <linux/types.h>
//#include <stdint.h>

typedef struct {
        uint8_t nonce[4];
        uint8_t iv[8];
        uint8_t ctr[4];
} rfc3686_blk;

#endif
