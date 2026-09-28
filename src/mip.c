#include <stdint.h>
#include "mip.h"

void mip_pack_header(uint8_t *buf, uint8_t dst, uint8_t src, uint8_t ttl, uint16_t sdu_len, uint8_t sdu_type) {
    
    uint16_t tail = ((ttl & 0x0F) << 12)
        | ((sdu_len & 0x1FF) << 3)
        |  (sdu_type & 0x07);

    buf[0] = dst;
    buf[1] = src;
    buf[2] = tail >> 8;
    buf[3] = tail & 0xFF;
}

void mip_unpack_header(const uint8_t *buf, uint8_t *dst, uint8_t *src, uint8_t *ttl, uint16_t *sdu_len, uint8_t *sdu_type) {
    
    uint16_t tail = (buf[2] << 8) | buf[3];

    *dst = buf[0];
    *src = buf[1];
    *ttl = (tail >> 12) & 0x0F;
    *sdu_len = (tail >> 3) & 0x1FF;
    *sdu_type = tail & 0x07;
}

