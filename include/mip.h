#ifndef MIP_H
#define MIP_H

#include <stdint.h>
#include <net/if.h>
#include <stddef.h>


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

#define MIP_HEADER_LEN 4

/* Represent one Ethernet interface on this host */
struct mip_iface {
    char name[IF_NAMESIZE];
    int ifindex;
    uint8_t mac[6];
};

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
 * This function writes exactly MIP_HEADER_LEN bytes to buf. It does not
 * allocate memory, return a value, or use global variables.
 *
 * The caller is responsible for providing a valid output buffer.
 */
void mip_pack_header(uint8_t *buf, uint8_t dst, uint8_t src,
                     uint8_t ttl, uint16_t sdu_len, uint8_t sdu_type);


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
 * This function does not allocate memory, return a value, or use global
 * variables. The output values are written through the supplied pointers.
 *
 * The caller is responsible for supplying valid, non-NULL pointers and
 * an input buffer of sufficient size.
 */
void mip_unpack_header(const uint8_t *buf, uint8_t *dst, uint8_t *src,
                       uint8_t *ttl, uint16_t *sdu_len, uint8_t *sdu_type);

                       
/**
 * Discover available Ethernet interfaces on the local host.
 *
 * ifaces: Output array that receives information about each discovered
 *         interface. The array must have space for at least MAX_IFACES
 *         struct mip_iface elements.
 *
 * Loopback interfaces are excluded. For every discovered interface, the
 * function stores its interface name, system interface index, and MAC
 * address in ifaces.
 *
 * Returns the number of interfaces stored in ifaces on success. Returns
 * -1 if interface discovery fails, for example because a system call
 * fails.
 *
 * This function does not allocate memory and does not depend on program
 * global variables. Interfaces beyond MAX_IFACES are not stored.
 */
int discover_interfaces(struct mip_iface *ifaces);


/**
 * Construct and transmit one Ethernet frame containing a MIP datagram.
 *
 * sd_raw: Open raw Ethernet socket used for transmission.
 * ifindex: System interface index of the outgoing Ethernet interface.
 * src_mac: Six-byte source Ethernet address to place in the frame.
 * dest_mac: Six-byte destination Ethernet address to place in the frame.
 * mip_dst: Destination MIP address to store in the MIP header.
 * mip_src: Source MIP address to store in the MIP header.
 * ttl: MIP Time To Live value.
 * sdu_type: Type of the encapsulated MIP SDU.
 * sdu: Pointer to the SDU payload to transmit.
 * sdu_len_bytes: Length of sdu in bytes. The value must be divisible by
 *                four because MIP SDUs must be 32-bit aligned.
 *
 * The function creates an Ethernet header with Ethertype ETH_P_MIP,
 * serializes a MIP header, appends the SDU, and sends the resulting frame
 * through sd_raw on ifindex.
 *
 * Returns 0 on success and -1 on failure. Failures can occur if memory
 * allocation, frame construction, or the underlying send operation fails.
 *
 * The function does not take ownership of sdu, src_mac, or dest_mac and
 * does not modify their contents. It does not use global variables.
 */
int send_mip_frame(int sd_raw, int ifindex,
                   const uint8_t *src_mac, const uint8_t *dest_mac,
                   uint8_t mip_dst, uint8_t mip_src, uint8_t ttl,
                   uint8_t sdu_type, const uint8_t *sdu, size_t sdu_len_bytes);

#endif


