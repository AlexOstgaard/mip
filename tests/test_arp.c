#include <stdio.h>
#include <stdint.h>
#include "mip_arp.h"
#include "mip.h"

int main(void)
{
    struct arp_entry cache[ARP_CACHE_SIZE] = {0};
    uint8_t test_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    arp_cache_insert(cache, 5, test_mac, 2);

    uint8_t out_mac[6];
    int out_ifindex;
    int found = arp_cache_lookup(cache, 5, out_mac, &out_ifindex);

    printf("found=%d ifindex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           found, out_ifindex,
           out_mac[0], out_mac[1], out_mac[2], out_mac[3], out_mac[4], out_mac[5]);

    found = arp_cache_lookup(cache, 99, out_mac, &out_ifindex);
    printf("found=%d (expected 0)\n", found);

    uint8_t buf[4];
    mip_arp_pack(buf, MIP_ARP_REQUEST, 5);
    printf("packed: %02x %02x %02x %02x (expected 00 05 00 00)\n",
           buf[0], buf[1], buf[2], buf[3]);

    uint8_t type, addr;
    mip_arp_unpack(buf, &type, &addr);
    printf("unpacked: type=%u addr=%u (expected type=0 addr=5)\n", type, addr);

    return 0;
}