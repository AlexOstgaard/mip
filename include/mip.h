#ifndef MIP_H
#define MIP_H

#include <stdint.h>
#include <net/if.h>

#ifndef ETH_P_MIP

/* Ethertype */
#define ETH_P_MIP 0x88B5
#endif

/* Reserved broadcast address*/
#define MIP_BROADCAST     0xFF

/* SDU types */
#define MIP_TYPE_ARP      0x01
#define MIP_TYPE_PING     0x02

/* ARP message-types */
#define MIP_ARP_REQUEST   0x00
#define MIP_ARP_RESPONSE  0x01

#define MAX_IFACES 8

/* Represent one Ethernet interface on this host */
struct mip_iface {
    char name[IF_NAMESIZE];
    int ifindex;
    uint8_t mac[6];
};

/* Pack the fields of a MIP header into a 4-byte buffer. */
void mip_pack_header(uint8_t *buf, uint8_t dst, uint8_t src,
                     uint8_t ttl, uint16_t sdu_len, uint8_t sdu_type);

/* Unpack 4-byte MIP header from buf to seperate fields. */
void mip_unpack_header(const uint8_t *buf, uint8_t *dst, uint8_t *src,
                       uint8_t *ttl, uint16_t *sdu_len, uint8_t *sdu_type);

/* Discover all Ethernet interfaces on this host, excluding loopback. */
int discover_interfaces(struct mip_iface *ifaces);

#endif


