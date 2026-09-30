#ifndef MIP_ARP_H
#define MIP_ARP_H

#include <stdint.h>
#include "mip.h"

#define ARP_CACHE_SIZE 16


/**
 * One entry in the fixed-size MIP-ARP cache.
 *
 * Each valid entry maps one MIP address to the Ethernet MAC address and
 * local interface associated with that MIP neighbour.
 *
 * mip_addr: MIP address represented by this cache entry.
 * mac: Six-byte Ethernet MAC address associated with mip_addr.
 * ifindex: System interface index on which the mapping was learned.
 * valid: Set to 1 when this entry contains a valid mapping, or 0 when
 *        the cache slot is unused.
 */
struct arp_entry {
    uint8_t mip_addr;
    uint8_t mac[6];
    int ifindex;
    int valid;
};


/**
 * Look up a MIP-to-MAC mapping in the MIP-ARP cache.
 *
 * cache: Array containing ARP_CACHE_SIZE cache entries.
 * mip_addr: MIP address to look up.
 * out_mac: Output buffer that receives the six-byte MAC address when a
 *          matching entry is found. The buffer must have room for at
 *          least six bytes.
 * out_ifindex: Output location that receives the local interface index
 *              associated with the cached mapping.
 *
 * Returns 1 if a valid cache entry matching mip_addr is found. In this
 * case, the corresponding MAC address and interface index are written
 * to out_mac and out_ifindex.
 *
 * Returns 0 if no valid matching entry exists. The output parameters
 * are not meaningful in this case.
 *
 * This function does not allocate memory and does not modify cache.
 * It does not use global variables. The caller must provide valid,
 * non-NULL pointers and a cache array with ARP_CACHE_SIZE entries.
 */
int arp_cache_lookup(struct arp_entry *cache, uint8_t mip_addr,
                     uint8_t *out_mac, int *out_ifindex);


/**
 * Store or update a MIP-to-MAC mapping in the MIP-ARP cache.
 *
 * cache: Array containing ARP_CACHE_SIZE cache entries.
 * mip_addr: MIP address to associate with mac and ifindex.
 * mac: Pointer to the six-byte Ethernet MAC address to store.
 * ifindex: System interface index on which this mapping was learned.
 *
 * If an existing valid entry for mip_addr is found, its MAC address and
 * interface index are updated. Otherwise, the function stores the new
 * mapping in an unused cache slot.
 *
 * The behaviour when the cache is full depends on the implementation;
 * it may discard the new mapping or replace an existing entry. This
 * should be documented in the implementation if a replacement policy
 * is used.
 *
 * This function does not allocate memory and does not use global
 * variables. It copies the MAC address into the cache and does not take
 * ownership of mac. The caller must provide valid, non-NULL pointers.
 */
void arp_cache_insert(struct arp_entry *cache, uint8_t mip_addr,
                      const uint8_t *mac, int ifindex);


/**
 * Serialize a MIP-ARP message into its four-byte SDU representation.
 *
 * buf: Output buffer for the serialized MIP-ARP message. It must have
 *      room for at least four bytes.
 * type: MIP-ARP message type, normally MIP_ARP_REQUEST or
 *       MIP_ARP_RESPONSE. Only the least significant bit is stored.
 * mip_addr: MIP address being requested or confirmed by the message.
 *
 * The resulting message consists of one type bit, eight address bits,
 * and 23 zero-valued reserved or padding bits, as specified for
 * MIP-ARP. This function writes exactly four bytes to buf.
 *
 * This function does not allocate memory, return a value, or use global
 * variables. The caller is responsible for providing a valid output
 * buffer.
 */
void mip_arp_pack(uint8_t *buf, uint8_t type, uint8_t mip_addr);


/**
 * Deserialize a four-byte MIP-ARP SDU.
 *
 * buf: Input buffer containing a serialized MIP-ARP message. The buffer
 *      must contain at least four bytes.
 * type: Output location for the one-bit MIP-ARP message type.
 * mip_addr: Output location for the MIP address contained in the
 *           message.
 *
 * The reserved and padding bits are ignored by this function. The
 * decoded type and address are written through type and mip_addr.
 *
 * This function does not allocate memory, return a value, or use global
 * variables. The caller must provide valid, non-NULL pointers.
 */
void mip_arp_unpack(const uint8_t *buf, uint8_t *type, uint8_t *mip_addr);

#endif