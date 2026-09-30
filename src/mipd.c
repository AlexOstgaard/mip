#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mip.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <poll.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include "mip_arp.h"

/*
 * Maximum SDU size that fits in the local Ethernet frame buffer:
 *
 * 1514 bytes total frame size
 * - 14 bytes Ethernet header
 * - 4 bytes MIP header
 * = 1496 bytes SDU
 */
#define MAX_PING_SDU_LEN 1496

/**
 * Stores one Ping SDU while the daemon waits for a MIP-ARP response.
 *
 * valid: Non-zero when this structure contains a pending Ping packet.
 * dst_mip: MIP address of the intended Ping recipient.
 * payload: Ping SDU received from the upper-layer client.
 * payload_len: Number of valid bytes in payload.
 */
struct pending_ping {
    int valid;
    uint8_t dst_mip;
    uint8_t payload[MAX_PING_SDU_LEN];
    size_t payload_len;
};



/**
 * Print command-line usage information for the MIP daemon.
 *
 * prog: Program name, normally argv[0]. The value is included in the
 *       printed usage line so that the message reflects how the program
 *       was invoked.
 *
 * The usage message is written to stderr.
 *
 * This function does not allocate memory, return a value, or modify
 * global variables.
 */
static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-h] [-d] <socket_upper> <MIP address>\n", prog);
}


/**
 * Create, bind, and listen on the UNIX domain socket used by upper-layer
 * applications to communicate with the MIP daemon.
 *
 * path: Filesystem path at which the UNIX domain socket is created.
 *       Any existing filesystem entry at this path is removed before
 *       binding the new socket.
 *
 * The created socket uses AF_UNIX and SOCK_SEQPACKET. The socket is put
 * into listening mode with a backlog of one client, because this
 * assignment supports only one upper-layer process at a time.
 *
 * Returns the listening socket file descriptor on success.
 *
 * If socket(), bind(), or listen() fails, an error message is printed
 * with perror() and the entire process terminates with exit status 1.
 *
 * This function modifies the filesystem by unlinking path when it
 * exists. It does not allocate dynamic memory or use global variables.
 */
int setup_unix_socket(const char *path)
{
    unlink(path);

    int sd = socket(AF_UNIX, SOCK_SEQPACKET, 0);

    if (sd == -1) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un sa_un;
    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    strncpy(sa_un.sun_path, path, sizeof(sa_un.sun_path) - 1);
    
    if (bind(sd, (struct sockaddr *)&sa_un, sizeof(sa_un)) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(sd, 1) == -1) {
        perror("listen");
        exit(1);
    }

    return sd;
}

/**
 * Create a raw Ethernet socket for receiving and transmitting MIP frames.
 *
 * The socket is created in the AF_PACKET domain with SOCK_RAW and is
 * configured for Ethernet frames with Ethertype ETH_P_MIP.
 *
 * Returns the raw socket file descriptor on success.
 *
 * If the socket cannot be created, for example because the process lacks
 * the CAP_NET_RAW capability or root privileges, perror() is called and
 * the entire process terminates with exit status 1.
 *
 * The returned file descriptor is owned by the caller and should be
 * closed when it is no longer needed. This function does not allocate
 * memory or use global variables.
 */
int setup_raw_socket(void) {

    int sd_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
    
    if (sd_raw == -1) {
        perror("socket (raw)");
        exit(1);
    }

    return sd_raw;
}

/**
 * Find the local MAC address associated with an interface index.
 *
 * ifaces: Array of discovered local Ethernet interfaces.
 * n_ifaces: Number of valid entries in ifaces.
 * ifindex: System interface index to search for.
 * out_mac: Output buffer that receives the matching six-byte MAC address.
 *          The buffer must have room for at least six bytes.
 *
 * Returns 1 when an interface with ifindex is found. Its MAC address is
 * copied to out_mac.
 *
 * Returns 0 when no matching interface exists. out_mac is not modified
 * in that case.
 *
 * This function does not allocate memory, modify ifaces, or use global
 * variables. The caller must provide valid pointers and a non-negative
 * n_ifaces value.
 */
int find_mac_by_ifindex(const struct mip_iface *ifaces, int n_ifaces,
                        int ifindex, uint8_t *out_mac)
{
    for (int i = 0; i < n_ifaces; i++) {
        if (ifaces[i].ifindex == ifindex) {
            memcpy(out_mac, ifaces[i].mac, 6);
            return 1;
        }
    }
    return 0;
}



/**
 * Discover local Ethernet interfaces, excluding the loopback interface.
 *
 * ifaces: Output array that receives discovered interface information.
 *         The array must have room for at least MAX_IFACES entries.
 *
 * For every discovered AF_PACKET interface, the function stores its name,
 * interface index, and six-byte Ethernet MAC address in ifaces. At most
 * MAX_IFACES interfaces are stored; any additional interfaces are
 * ignored.
 *
 * Returns the number of interfaces stored in ifaces.
 *
 * If getifaddrs() fails, perror() is called and the entire process
 * terminates with exit status 1.
 *
 * This function allocates no memory directly, but uses getifaddrs(),
 * whose result is released with freeifaddrs() before returning. It does
 * not use global variables.
 */
int discover_interfaces(struct mip_iface *ifaces)
{
    struct ifaddrs *addrs, *ifa;
    int count = 0;

    if (getifaddrs(&addrs) == -1) {
        perror("getifaddrs");
        exit(1);
    }

    for (ifa = addrs; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET)
            continue;
        if (strcmp(ifa->ifa_name, "lo") == 0)
            continue;
        if (count >= MAX_IFACES)
            break;

        struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;

        strncpy(ifaces[count].name, ifa->ifa_name, IF_NAMESIZE - 1);
        ifaces[count].name[IF_NAMESIZE - 1] = '\0';

        ifaces[count].ifindex = sll->sll_ifindex;
        memcpy(ifaces[count].mac, sll->sll_addr, 6);
        count++;

    }

    freeifaddrs(addrs);
    return count;
}

/**
 * Receive and process one MIP Ethernet frame from the raw socket.
 *
 * sd_raw: Raw AF_PACKET socket from which the Ethernet frame is received
 *         and through which an ARP response may be transmitted.
 * debug: Non-zero enables diagnostic output about received Ethernet and
 *        MIP headers.
 * cache: MIP-ARP cache to update when ARP traffic is received.
 * my_mip_addr: MIP address assigned to this local daemon.
 * ifaces: Array of local Ethernet interface descriptions.
 * n_ifaces: Number of valid entries in ifaces.
 *
 * The function receives one Ethernet frame, verifies that it has MIP
 * Ethertype ETH_P_MIP, decodes the MIP header, and verifies that the
 * received frame contains the SDU length claimed by that header.
 *
 * MIP-ARP requests targeting my_mip_addr cause the sender mapping to be
 * inserted into cache. The function then sends a unicast MIP-ARP
 * response on the interface on which the request arrived. MIP-ARP
 * responses cause the sender mapping to be inserted into cache.
 *
 * Ping SDUs addressed to my_mip_addr are delivered to the connected
 * upper-layer client as one source MIP address byte followed by the SDU.
 * Ping SDUs for other MIP addresses are ignored because this daemon does
 * not implement packet forwarding.

 *
 * This function returns no value. Receive errors and malformed frames are
 * reported to stderr and ignored. It modifies cache when processing ARP
 * messages, but does not use global variables.
 */
void handle_raw_socket(int sd_raw, int client_sd, int debug,
                       struct arp_entry *cache,
                       struct pending_ping *pending,
                       uint8_t my_mip_addr,
                       const struct mip_iface *ifaces, int n_ifaces)

{
    uint8_t buf[1514];
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    ssize_t n = recvfrom(sd_raw, buf, sizeof(buf), 0,
                         (struct sockaddr *)&src_addr, &addr_len);

    if (n == -1) {
        perror("recvfrom");
        return;
    }

    if (n < (ssize_t)(sizeof(struct ethhdr) + MIP_HEADER_LEN)) {
        fprintf(stderr, "Frame too short to contain Ethernet and MIP headers\n");
        return;
    }


    struct ethhdr *eth = (struct ethhdr *)buf;

    if (ntohs(eth->h_proto) != ETH_P_MIP) {
        return;
    }

    uint8_t *mip_hdr_start = buf + sizeof(struct ethhdr);
    uint8_t dst, src, ttl, sdu_type;
    uint16_t sdu_len;

    mip_unpack_header(mip_hdr_start, &dst, &src, &ttl, &sdu_len, &sdu_type);

    uint8_t *sdu = mip_hdr_start + MIP_HEADER_LEN;
    size_t sdu_len_bytes = sdu_len * 4;

    size_t expected_len = sizeof(struct ethhdr) + MIP_HEADER_LEN + sdu_len_bytes;
    if ((size_t)n < expected_len) {
        fprintf(stderr, "Frame shorter than SDU length claims\n");
        return;
    }

    if (debug) {
        printf("Ethernet: src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5],
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("MIP: src=%u dst=%u ttl=%u sdu_type=%u sdu_len=%zu bytes, from ifindex=%d\n",
               src, dst, ttl, sdu_type, sdu_len_bytes, src_addr.sll_ifindex);
    }

    if (sdu_type == MIP_TYPE_ARP) {
        if (sdu_len_bytes != 4) {
            if (debug) {
                printf("Ignoring MIP-ARP SDU with invalid length %zu bytes\n",
                       sdu_len_bytes);
            }
            return;
        }

        uint8_t arp_type, arp_addr;
        mip_arp_unpack(sdu, &arp_type, &arp_addr);

        if (arp_type == MIP_ARP_REQUEST) {
            if (arp_addr == my_mip_addr) {
                arp_cache_insert(cache, src, eth->h_source, src_addr.sll_ifindex);

                if (debug) {
                    arp_cache_print(cache);
                }

                uint8_t my_mac[6];
                if (find_mac_by_ifindex(ifaces, n_ifaces, src_addr.sll_ifindex, my_mac)) {
                    uint8_t response_sdu[4];
                    mip_arp_pack(response_sdu, MIP_ARP_RESPONSE, my_mip_addr);

                    send_mip_frame(sd_raw, src_addr.sll_ifindex,
                                  my_mac, eth->h_source,
                                  src, my_mip_addr, 1,
                                  MIP_TYPE_ARP, response_sdu, sizeof(response_sdu));
                } else if (debug) {
                    printf("Could not find MAC for ifindex=%d, dropping ARP response\n",
                           src_addr.sll_ifindex);
                }
            }
        } else if (arp_type == MIP_ARP_RESPONSE) {
            arp_cache_insert(cache, src, eth->h_source, src_addr.sll_ifindex);
        
            if (debug) {
                arp_cache_print(cache);
            }
            /*
             * If this ARP response is for the MIP address of the saved Ping,
             * transmit the saved packet now.
             */
            if (pending->valid && pending->dst_mip == src) {
                uint8_t my_mac[6];
            
                if (!find_mac_by_ifindex(ifaces, n_ifaces,
                                         src_addr.sll_ifindex, my_mac)) {
                    fprintf(stderr,
                            "No local interface found for ARP response interface\n");
                    return;
                }
            
                if (send_mip_frame(sd_raw, src_addr.sll_ifindex,
                                   my_mac, eth->h_source,
                                   pending->dst_mip, my_mip_addr, 1,
                                   MIP_TYPE_PING,
                                   pending->payload,
                                   pending->payload_len) == -1) {
                    perror("send pending MIP Ping frame");
                    return;
                }
            
                /*
                 * The Ping was sent successfully. Clear it immediately, so a
                 * duplicate ARP response cannot trigger another transmission.
                 */
                pending->valid = 0;
            
                if (debug) {
                    printf("Sent pending Ping to MIP address %u after ARP response\n",
                           pending->dst_mip);
                }
            }
        }
    } else if (sdu_type == MIP_TYPE_PING) {
        /*
        * This daemon does not route packets. Only accept Ping messages
        * addressed directly to this host.
        */ 
        if (dst != my_mip_addr) {
            if (debug) {
                printf("Ignoring Ping for MIP address %u\n", dst);
            }
            return;
        }

        if (client_sd == -1) {
            if (debug) {
                printf("No upper-layer client connected; dropping Ping\n");
            }
            return;
        }

        uint8_t upper_msg[1500];

        if (sdu_len_bytes + 1 > sizeof(upper_msg)) {
            fprintf(stderr, "Ping SDU too large for upper-layer buffer\n");
            return;
        }

        /*
        * Message format toward upper layer:
        * one source MIP address byte followed by the received SDU.
        */
        upper_msg[0] = src;
        memcpy(upper_msg + 1, sdu, sdu_len_bytes);

        ssize_t sent = send(client_sd, upper_msg, sdu_len_bytes + 1, 0);
        if (sent == -1) {
            perror("send to upper layer");
        } else if ((size_t)sent != sdu_len_bytes + 1) {
            fprintf(stderr, "Incomplete message sent to upper layer\n");
        }

    } else {
        if (debug)
            printf("Unknown SDU type %u, ignoring\n", sdu_type);
    }
}

/**
 * Construct and transmit one Ethernet frame containing a MIP datagram.
 *
 * sd_raw: Open AF_PACKET raw socket used for frame transmission.
 * ifindex: System interface index of the outgoing Ethernet interface.
 * src_mac: Pointer to the six-byte source Ethernet MAC address.
 * dest_mac: Pointer to the six-byte destination Ethernet MAC address.
 * mip_dst: Destination MIP address to write to the MIP header.
 * mip_src: Source MIP address to write to the MIP header.
 * ttl: MIP Time To Live value. mip_pack_header() stores its low four bits.
 * sdu_type: Type of the MIP SDU. mip_pack_header() stores its low three
 *           bits.
 * sdu: Pointer to the SDU payload. It may be NULL only when
 *      sdu_len_bytes is zero.
 * sdu_len_bytes: Length of sdu in bytes. The value must be divisible by
 *                four because MIP SDUs are measured in 32-bit words.
 *
 * The function creates an Ethernet header with Ethertype ETH_P_MIP,
 * serializes a four-byte MIP header, appends the SDU, and sends the
 * resulting frame with sendto() through sd_raw on ifindex.
 *
 * Returns 0 on success.
 *
 * Returns -1 on failure and sets errno. EINVAL indicates invalid
 * pointers, an invalid interface index, or an SDU length that is not
 * divisible by four. EMSGSIZE indicates that the constructed frame is
 * larger than the local frame buffer. EIO indicates that sendto()
 * returned a partial transmission. Errors reported directly by sendto()
 * are propagated through errno.
 *
 * This function does not allocate dynamic memory and does not modify or
 * take ownership of src_mac, dest_mac, or sdu. It does not use global
 * variables.
 */
int send_mip_frame(int sd_raw, int ifindex,
                   const uint8_t *src_mac, const uint8_t *dest_mac,
                   uint8_t mip_dst, uint8_t mip_src, uint8_t ttl,
                   uint8_t sdu_type, const uint8_t *sdu,
                   size_t sdu_len_bytes)
{
    uint8_t frame[1514];
    size_t offset = 0;

    if (src_mac == NULL || dest_mac == NULL ||
        (sdu == NULL && sdu_len_bytes != 0)) {
        errno = EINVAL;
        return -1;
    }

    if (ifindex <= 0) {
        errno = EINVAL;
        return -1;
    }

    /*
     * The MIP SDU length field counts 32-bit words, rather than bytes.
     * Therefore all SDUs must have a length divisible by four bytes.
     */
    if (sdu_len_bytes % 4 != 0) {
        errno = EINVAL;
        return -1;
    }

    size_t frame_len = sizeof(struct ethhdr) +
                       MIP_HEADER_LEN +
                       sdu_len_bytes;

    if (frame_len > sizeof(frame)) {
        errno = EMSGSIZE;
        return -1;
    }

    size_t sdu_len_words_size = sdu_len_bytes / 4;

    /*
     * mip_pack_header() takes uint16_t. Check before conversion so a
     * too-large value cannot silently wrap around.
     */
    if (sdu_len_words_size > MIP_MAX_SDU_WORDS) {
        errno = EMSGSIZE;
        return -1;
    }


    uint16_t sdu_len_words = (uint16_t)sdu_len_words_size;

    /* Build Ethernet header. */
    struct ethhdr *eth = (struct ethhdr *)frame;

    memcpy(eth->h_dest, dest_mac, ETH_ALEN);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_MIP);

    offset += sizeof(struct ethhdr);

    /* Build the four-byte MIP header. */
    mip_pack_header(frame + offset,
                    mip_dst,
                    mip_src,
                    ttl,
                    sdu_len_words,
                    sdu_type);

    offset += MIP_HEADER_LEN;

    /* Append SDU only when it has content. */
    if (sdu_len_bytes > 0) {
        memcpy(frame + offset, sdu, sdu_len_bytes);
        offset += sdu_len_bytes;
    }

    /*
     * sockaddr_ll specifies the Ethernet interface and destination
     * link-layer address used by the AF_PACKET socket.
     */
    struct sockaddr_ll dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_protocol = htons(ETH_P_MIP);
    dest_addr.sll_ifindex = ifindex;
    dest_addr.sll_halen = ETH_ALEN;
    memcpy(dest_addr.sll_addr, dest_mac, ETH_ALEN);

    ssize_t sent = sendto(sd_raw, frame, offset, 0,
                          (struct sockaddr *)&dest_addr,
                          sizeof(dest_addr));

    if (sent == -1) {
        return -1;
    }

    /*
     * AF_PACKET/SOCK_RAW normally either transmits all bytes or returns
     * an error, but checking makes the function robust.
     */
    if ((size_t)sent != offset) {
        errno = EIO;
        return -1;
    }

    return 0;
}


/**
 * Run the main event loop of the MIP daemon.
 *
 * sd_upper: Listening UNIX domain socket for upper-layer applications.
 * sd_raw: Raw AF_PACKET socket for incoming and outgoing MIP Ethernet
 *         frames.
 * debug: Non-zero enables diagnostic output.
 * cache: MIP-ARP cache shared with received-frame processing.
 * my_mip_addr: MIP address assigned to this daemon.
 * ifaces: Array of discovered local Ethernet interfaces.
 * n_ifaces: Number of valid entries in ifaces.
 *
 * The function uses poll() to wait for activity on the listening UNIX
 * socket, the raw Ethernet socket, and, when connected, one upper-layer
 * client socket. It accepts one upper-layer client at a time.
 *
 * Incoming raw Ethernet frames are passed to handle_raw_socket().
 * Messages received from the upper-layer client consist of one destination
 * MIP address byte followed by an SDU payload. If the destination has a
 * cached MIP-ARP mapping, the payload is transmitted as a MIP Ping frame.
 * Otherwise, the daemon broadcasts a MIP-ARP request for the destination.
 *
 * The function normally runs indefinitely and returns only if poll()
 * fails. A poll() failure is reported with perror().
 *
 * This function modifies cache through handle_raw_socket() and owns the
 * local client socket descriptor while the event loop runs. It does not
 * allocate dynamic memory or use global variables.
 */
void run_daemon(int sd_upper, int sd_raw, int debug,
                struct arp_entry *cache, struct pending_ping *pending,
                uint8_t my_mip_addr, struct mip_iface *ifaces, int n_ifaces) {

    int client_sd = -1;

    while (1) {
        struct pollfd fds[3];
        int nfds = 0;

        fds[nfds].fd = sd_upper;
        fds[nfds].events = POLLIN;
        nfds++;

        fds[nfds].fd = sd_raw;
        fds[nfds].events = POLLIN;
        nfds++;

        int client_idx = -1;
        if (client_sd != -1) {
            fds[nfds].fd = client_sd;
            fds[nfds].events = POLLIN;
            client_idx = nfds;
            nfds++;
        }

        int ret = poll(fds, nfds, -1);
        if (ret == -1) {
            perror("poll");
            break;
        }

        /* New client wants to connect */
        if (fds[0].revents & POLLIN) {
            client_sd = accept(sd_upper, NULL, NULL);
            if (debug)
                printf("New client connected, fd=%d\n", client_sd);
        }

        /* Raw Ethernet frame has arrived */
        if (fds[1].revents & POLLIN) {
            handle_raw_socket(sd_raw, client_sd, debug, cache, pending,
                              my_mip_addr, ifaces, n_ifaces);
        }

        /* Connected client has sent something */
        if (client_idx != -1 && (fds[client_idx].revents & POLLIN)) {
            uint8_t buf[1500];
            ssize_t n = recv(client_sd, buf, sizeof(buf), 0);

            if (n <= 0) {
                if (n == 0) {
                    printf("Client closed the connection\n");
                } else {
                    perror("recv");
                }
                close(client_sd);
                client_sd = -1;
            } else {
                /*
                 * The first byte received from the upper layer is the
                 * destination MIP address. The remaining bytes are the SDU.
                 */
                if (n < 1) {
                    fprintf(stderr, "Received empty message from upper layer\n");
                    continue;
                }

                uint8_t dest_mip = buf[0];
                uint8_t *payload = &buf[1];
                size_t payload_len = (size_t)n - 1;

                /*
                 * The MIP header stores the SDU length in 32-bit words.
                 * Therefore the supplied SDU must have a byte length divisible
                 * by four.
                 */
                if (payload_len % 4 != 0) {
                    fprintf(stderr,
                            "Upper-layer payload length must be divisible by 4 bytes\n");
                    continue;
                }

                if (debug) {
                    printf("Received upper-layer message for MIP address %u, "
                            "%zu bytes payload: %.*s\n",
                            dest_mip, payload_len, (int)payload_len, payload);
                }

                uint8_t dest_mac[6];
                int out_ifindex;

                /*
                 * A cached mapping allows the Ping SDU to be sent immediately.
                 */
                if (arp_cache_lookup(cache, dest_mip, dest_mac, &out_ifindex)) {
                    uint8_t src_mac[6];

                    if (!find_mac_by_ifindex(ifaces, n_ifaces,
                                             out_ifindex, src_mac)) {
                        fprintf(stderr,
                                "No local interface found for cached ARP entry\n");
                        continue;
                    }

                    if (send_mip_frame(sd_raw, out_ifindex,
                                       src_mac, dest_mac,
                                       dest_mip, my_mip_addr, 1,
                                        MIP_TYPE_PING, payload, payload_len) == -1) {
                        perror("send MIP Ping frame");
                    }
                } else {
                    
                    if (pending->valid) {
                        fprintf(stderr,
                                "Already waiting for an ARP response; dropping Ping packet\n");
                        continue;
                    }
                
                    if (payload_len > sizeof(pending->payload)) {
                        fprintf(stderr, "Ping payload is too large\n");
                        continue;
                    }
                
                    pending->dst_mip = dest_mip;
                    pending->payload_len = payload_len;
                    memcpy(pending->payload, payload, payload_len);
                    pending->valid = 1;
                
                    uint8_t broadcast_mac[6] = {
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
                    };

                    uint8_t arp_sdu[4];
                    mip_arp_pack(arp_sdu, MIP_ARP_REQUEST, dest_mip);

                    if (debug) {
                        printf("No MIP-ARP cache entry for MIP address %u; "
                                "broadcasting ARP request\n",
                            dest_mip);
                    }

                    for (int i = 0; i < n_ifaces; i++) {
                        if (send_mip_frame(sd_raw, ifaces[i].ifindex,
                                           ifaces[i].mac, broadcast_mac,
                                           MIP_BROADCAST, my_mip_addr, 1,
                                           MIP_TYPE_ARP, arp_sdu, sizeof(arp_sdu)) == -1) {
                            perror("send MIP-ARP request");
                        }
                    }

                    /*
                     * The original Ping SDU must be saved here so it can be transmitted
                     * when a matching MIP-ARP response is received.
                     */
                }
            }
        }
    }
}


/**
 * Start and configure the MIP daemon.
 *
 * argc: Number of command-line arguments.
 * argv: Command-line argument array.
 *
 * The program accepts the options -h and -d, followed by a UNIX socket
 * path and a MIP address in the range 0 through 254. Address 255 is
 * rejected because it is reserved as the MIP broadcast address.
 *
 * The function creates the upper-layer UNIX socket, discovers local
 * Ethernet interfaces, creates the raw Ethernet socket, initializes an
 * empty MIP-ARP cache, and enters the daemon event loop.
 *
 * Returns 0 when -h is requested. Returns 1 for invalid command-line
 * input. Under normal operation, run_daemon() does not return.
 *
 * Several setup failures are handled by helper functions that print an
 * error and terminate the process. This function has no global variables.
 */
int main(int argc, char *argv[]) {

    int opt;
    int debug = 0;

    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch (opt) {
            case 'h': print_usage(argv[0]); return 0;
            case 'd': debug = 1; break;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (argc - optind != 2) {
        fprintf(stderr, "Missing arguments\n");
        print_usage(argv[0]);
        return 1;
    }

    char* socket_upper = argv[optind];
    char* mip_address_text = argv[optind + 1];
    char *endptr;

    long mip_address = strtol(mip_address_text, &endptr, 10);

    if (endptr == mip_address_text || *endptr != '\0' || mip_address < 0 || mip_address >= MIP_BROADCAST) {
        fprintf(stderr, "Invalid address, must be 0-254\n");
        return 1;
    }

    if (debug)
        printf("socket=%s address=%ld\n", socket_upper, mip_address);

    int sd_upper = setup_unix_socket(socket_upper);
    if (debug)
        printf("UNIX socket bound and listening on %s (fd=%d)\n", socket_upper, sd_upper);

    struct mip_iface ifaces[MAX_IFACES];
    int n_ifaces = discover_interfaces(ifaces);

    for (int i = 0; i < n_ifaces; i++) {
        printf("Interface: %s, ifindex=%d, MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
        ifaces[i].name, ifaces[i].ifindex,
        ifaces[i].mac[0], ifaces[i].mac[1], ifaces[i].mac[2],
        ifaces[i].mac[3], ifaces[i].mac[4], ifaces[i].mac[5]);
    }

    int sd_raw = setup_raw_socket();

    if (debug)
        printf("Raw socket created (fd=%d)\n", sd_raw);

    
    struct arp_entry arp_cache[ARP_CACHE_SIZE] = {0};
    struct pending_ping pending = {0};

    run_daemon(sd_upper, sd_raw, debug, arp_cache, &pending,
               (uint8_t)mip_address, ifaces, n_ifaces);

    return 0;
}