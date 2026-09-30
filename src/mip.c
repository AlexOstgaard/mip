#include "mip.h"

/**
 * Serialize MIP header fields into the four-byte MIP wire format.
 *
 * buf: Output buffer for the serialized header. The buffer must have
 *      room for at least MIP_HEADER_LEN bytes.
 * dst: Destination MIP address.
 * src: Source MIP address.
 * ttl: Time To Live value. Only the least significant four bits are
 *      stored in the header.
 * sdu_len: SDU length measured in 32-bit words. Only the least
 *          significant nine bits are stored in the header.
 * sdu_type: Type of the encapsulated SDU. Only the least significant
 *           three bits are stored in the header.
 *
 * The function writes exactly MIP_HEADER_LEN bytes to buf. It does not
 * allocate memory, return a value, or use global variables.
 *
 * The caller is responsible for providing a valid output buffer.
 */
void mip_pack_header(uint8_t *buf, uint8_t dst, uint8_t src,
                     uint8_t ttl, uint16_t sdu_len, uint8_t sdu_type)
{
    uint16_t tail = (uint16_t)(((ttl & 0x0F) << 12)
                  | ((sdu_len & 0x01FF) << 3)
                  | (sdu_type & 0x07));

    buf[0] = dst;
    buf[1] = src;
    buf[2] = (uint8_t)(tail >> 8);
    buf[3] = (uint8_t)(tail & 0xFF);
}

/**
 * Deserialize a four-byte MIP header from its wire representation.
 *
 * buf: Input buffer containing a serialized MIP header. The buffer must
 *      contain at least MIP_HEADER_LEN bytes.
 * dst: Output location for the destination MIP address.
 * src: Output location for the source MIP address.
 * ttl: Output location for the four-bit Time To Live value.
 * sdu_len: Output location for the nine-bit SDU length, measured in
 *          32-bit words.
 * sdu_type: Output location for the three-bit SDU type.
 *
 * The decoded field values are written through the output pointers.
 * This function does not allocate memory, modify buf, return a value,
 * or use global variables.
 *
 * The caller must provide valid, non-NULL pointers and an input buffer
 * containing at least MIP_HEADER_LEN bytes.
 */
void mip_unpack_header(const uint8_t *buf, uint8_t *dst, uint8_t *src,
                       uint8_t *ttl, uint16_t *sdu_len, uint8_t *sdu_type)
{
    uint16_t tail = (uint16_t)(((uint16_t)buf[2] << 8) | buf[3]);

    *dst = buf[0];
    *src = buf[1];
    *ttl = (uint8_t)((tail >> 12) & 0x0F);
    *sdu_len = (uint16_t)((tail >> 3) & 0x01FF);
    *sdu_type = (uint8_t)(tail & 0x07);
}
