#ifndef MIP_ARP_H
#define MIP_ARP_H

#include <stdint.h>

#define ARP_CACHE_SIZE 16

#define MIP_ARP_REQUEST   0x00
#define MIP_ARP_RESPONSE  0x01

/**
 * One entry in the MIP-ARP cache: maps a MIP address to the MAC
 * address and interface it was learned on.
 * valid: 0 if this slot is empty/unused, 1 if it holds a real entry.
 */
struct arp_entry {
    uint8_t mip_addr;
    uint8_t mac[6];
    int ifindex;
    int valid;
};

int arp_cache_lookup(struct arp_entry *cache, uint8_t mip_addr,
                     uint8_t *out_mac, int *out_ifindex);

void arp_cache_insert(struct arp_entry *cache, uint8_t mip_addr,
                      const uint8_t *mac, int ifindex);

void mip_arp_pack(uint8_t *buf, uint8_t type, uint8_t mip_addr);
void mip_arp_unpack(const uint8_t *buf, uint8_t *type, uint8_t *mip_addr);

#endif