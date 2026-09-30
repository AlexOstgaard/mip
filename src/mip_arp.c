#include <stdio.h>
#include <string.h>
#include "mip_arp.h"

/**
 * Look up a MIP-to-MAC mapping in the fixed-size MIP-ARP cache.
 *
 * cache: Array containing ARP_CACHE_SIZE struct arp_entry elements.
 * mip_addr: MIP address to search for.
 * out_mac: Output buffer that receives the matching six-byte Ethernet
 *          MAC address when a valid entry is found. The buffer must have
 *          space for at least six bytes.
 * out_ifindex: Output location that receives the interface index stored
 *              with the matching cache entry.
 *
 * Returns 1 if a valid cache entry for mip_addr is found. In this case,
 * the matching MAC address and interface index are copied to out_mac and
 * out_ifindex.
 *
 * Returns 0 if no valid matching entry exists. out_mac and out_ifindex
 * are not modified when the lookup fails.
 *
 * This function does not allocate memory, modify the cache, or use
 * global variables. The caller must provide valid, non-NULL pointers.
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
 * Insert or update a MIP-to-MAC mapping in the fixed-size MIP-ARP cache.
 *
 * cache: Array containing ARP_CACHE_SIZE struct arp_entry elements.
 * mip_addr: MIP address to associate with the supplied MAC address and
 *           interface index.
 * mac: Pointer to the six-byte Ethernet MAC address to store.
 * ifindex: System interface index on which the mapping was learned.
 *
 * If cache already contains a valid entry for mip_addr, its MAC address
 * and interface index are updated. Otherwise, the mapping is stored in
 * the first unused cache slot.
 *
 * If no unused cache slot is available, the new mapping is discarded and
 * an error message is printed to stderr. Existing cache entries are not
 * replaced when the cache is full.
 *
 * This function does not allocate memory and does not return a value.
 * It modifies cache, but does not modify or take ownership of mac. It
 * does not use global variables. The caller must provide valid, non-NULL
 * pointers.
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
 * Serialize a MIP-ARP request or response into a four-byte SDU buffer.
 *
 * buf: Output buffer for the serialized MIP-ARP message. The buffer must
 *      have room for at least four bytes.
 * type: MIP-ARP message type to store. The current implementation writes
 *       this value directly to the first byte of the message.
 * mip_addr: MIP address being looked up in a request, or the MIP address
 *           that matched in a response.
 *
 * The function writes type and mip_addr to the first two bytes of buf and
 * clears the final two bytes as padding. It writes exactly four bytes.
 *
 * This function does not allocate memory, return a value, or use global
 * variables. The caller must supply a valid output buffer.
 */
void mip_arp_pack(uint8_t *buf, uint8_t type, uint8_t mip_addr)
{
    buf[0] = type;
    buf[1] = mip_addr;
    buf[2] = 0x00;
    buf[3] = 0x00;
}

/**
 * Deserialize the type and MIP address from a four-byte MIP-ARP SDU.
 *
 * buf: Input buffer containing at least four bytes of MIP-ARP data.
 * type: Output location that receives the MIP-ARP message type stored
 *       in the first byte of buf.
 * mip_addr: Output location that receives the MIP address stored in the
 *           second byte of buf.
 *
 * The final two bytes of the message are treated as padding and ignored.
 *
 * This function does not allocate memory, modify buf, return a value, or
 * use global variables. The caller must provide valid, non-NULL pointers.
 */
void mip_arp_unpack(const uint8_t *buf, uint8_t *type, uint8_t *mip_addr)
{
    *type = buf[0];
    *mip_addr = buf[1];
}