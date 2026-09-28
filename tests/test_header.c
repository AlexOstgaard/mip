#include <stdio.h>
#include <stdint.h>
#include "mip.h"

int main(void)
{
    uint8_t buf[4];
    mip_pack_header(buf, 5, 1, 1, 3, 2);   /* maks for ttl, sdu_len og type */
    printf("%02x %02x %02x %02x\n", buf[0], buf[1], buf[2], buf[3]);

    uint8_t dst, src, ttl, sdu_type;
    uint16_t sdu_len;
    mip_unpack_header(buf, &dst, &src, &ttl, &sdu_len, &sdu_type);
    printf("dst=%u src=%u ttl=%u sdu_len=%u sdu_type=%u\n",
           dst, src, ttl, sdu_len, sdu_type);

    if (dst == 5 && src == 1 && ttl == 1 && sdu_len == 3 && sdu_type == 2)
        printf("OK\n");
    else
        printf("FEIL\n");

    return 0;
}