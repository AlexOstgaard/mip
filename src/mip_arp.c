#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mip_arp.h"

/**
 * Look up a MIP address in the ARP cache.
 * cache: the cache array, ARP_CACHE_SIZE entries.
 * mip_addr: the MIP address to look up.
 * out_mac: output, filled with the matching MAC address if found.
 *          Must point to a buffer of at least 6 bytes.
 * out_ifindex: output, filled with the matching interface index if found.
 * Returns 1 if an entry was found, 0 otherwise. out_mac/out_ifindex
 * are left untouched if not found.
 */
int arp_cache_lookup(struct arp_entry *cache, uint8_t mip_addr,
                     uint8_t *out_mac, int *out_ifindex)
{
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].mip_addr == mip_addr) {
            memcpy(out_mac, cache[i].mac, 6);
            *out_ifindex = cache[i].ifindex;
            return 1;
        }
    }
    return 0;
}

/**
 * Insert or update an entry in the ARP cache.
 * cache: the cache array, ARP_CACHE_SIZE entries.
 * mip_addr: the MIP address to store.
 * mac: the corresponding MAC address, 6 bytes.
 * ifindex: the interface this mapping was learned on.
 * If mip_addr already has an entry, it is overwritten with the new
 * mac/ifindex. Otherwise the first free slot is used. If the cache
 * is full, the entry is dropped and a message is printed to stderr.
 * No return value.
 */
void arp_cache_insert(struct arp_entry *cache, uint8_t mip_addr,
                      const uint8_t *mac, int ifindex)
{

    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (cache[i].valid && cache[i].mip_addr == mip_addr) {
            memcpy(cache[i].mac, mac, 6);
            cache[i].ifindex = ifindex;
            return;
        }
    }


    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!cache[i].valid) {
            cache[i].mip_addr = mip_addr;
            memcpy(cache[i].mac, mac, 6);
            cache[i].ifindex = ifindex;
            cache[i].valid = 1;
            return;
        }
    }


    fprintf(stderr, "ARP cache full, dropping entry for MIP address %u\n", mip_addr);
}

/**
 * Pack a MIP-ARP message into a 4-byte buffer.
 * buf: output buffer, must hold at least 4 bytes.
 * type: MIP_ARP_REQUEST or MIP_ARP_RESPONSE.
 * mip_addr: the MIP address being requested (request) or that
 *           matched (response).
 * The remaining 2 bytes are zero-padded, per the specification.
 */
void mip_arp_pack(uint8_t *buf, uint8_t type, uint8_t mip_addr)
{
    buf[0] = type;
    buf[1] = mip_addr;
    buf[2] = 0x00;
    buf[3] = 0x00;
}

/**
 * Unpack a 4-byte MIP-ARP message.
 * buf: input buffer, must hold at least 4 bytes.
 * type, mip_addr: output pointers, must not be NULL.
 * Padding bytes are ignored.
 */
void mip_arp_unpack(const uint8_t *buf, uint8_t *type, uint8_t *mip_addr)
{
    *type = buf[0];
    *mip_addr = buf[1];
}