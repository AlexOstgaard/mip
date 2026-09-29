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


/*
 Print usage information to stderr. 
 prog-parameter is the program's own name (argv[0]), 
 used so the message matches however the program was invoked. No return value.
 */
static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-h] [-d] <socket_upper> <MIP address>\n", prog);
}


/*
 Create and bind a UNIX domain socket for communication with the upper layer applications.
 path-parameter is for the filesystem path to bind the socket to. 
 Any existing file at this path is removed first.
 * Returns the socket descriptor.
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

/* 
Create a raw AF_PACKET socket for sending and receiving 
Ethernet frames with the MIP ethertype, on all interfaces.
*/
int setup_raw_socket(void) {

    int sd_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
    
    if (sd_raw == -1) {
        perror("socket (raw)");
        exit(1);
    }

    return sd_raw;
}


/*
Discover all Ethernet interfaces (excluding loopback) on this host.
Returns the number of interfaces found, written into ifaces[0..n-1].
Exits the program on fatal error (getifaddrs failure).
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
        ifaces[count].ifindex = sll->sll_ifindex;
        memcpy(ifaces[count].mac, sll->sll_addr, 6);
        count++;
    }

    freeifaddrs(addrs);
    return count;
}

/*
Handle activity on the raw AF_PACKET socket: receive one Ethernet
frame, and print which interface it arrived on.
*/
void handle_raw_socket(int sd_raw, int debug)
{
    uint8_t buf[1514];
    struct sockaddr_ll src_addr;
    socklen_t addr_len = sizeof(src_addr);

    ssize_t n = recvfrom(
        sd_raw, 
        buf, 
        sizeof(buf), 
        0, 
        (struct sockaddr *)&src_addr, 
        &addr_len
    );

    if (n == -1) {
        perror("recvfrom");
        return;
    }

    if (n < (ssize_t)sizeof(struct ethhdr)) {
        fprintf(stderr, "Frame too short to contain an Ethernet header\n");
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

    size_t expected_len = sizeof(struct ethhdr) + 4 + sdu_len_bytes;
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
        
    } else if (sdu_type == MIP_TYPE_PING) {
        
    } else {
        if (debug)
            printf("Unknown SDU type %u, ignoring\n", sdu_type);
    }

    (void)sdu;
}

/*
Build a MIP frame (Ethernet header + MIP header + SDU) and send
it on the given raw socket and interface.

Returns 0 on success, -1 on failure with errno set (EINVAL for
bad arguments or misaligned SDU length, EMSGSIZE if the frame or
SDU length is too large, EIO if sendto() sent fewer bytes than
expected, or an error from sendto() itself).
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
    if (sdu_len_words_size > UINT16_MAX) {
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


/*
Run MIP daemon's main event loop.

Waits for activity on the listening upper-layer UNIX socket and, 
once a client is connected, on that client's socket as well, using poll(). 
Accepts new client connections, and reads and prints messages received from the connected client. 
Only one upper-layer client is supported at a time, per the assignment specification.
Once a client disconnects, the daemon goes back to waiting for a new connection.
*/
void run_daemon(int sd_upper, int sd_raw, int debug) {

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
            handle_raw_socket(sd_raw, debug);
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
                uint8_t dest_mip = buf[0];
                uint8_t *payload = &buf[1];
                size_t payload_len = n - 1;
                printf("Received message for/from MIP address %u, %zu bytes payload: %.*s\n",
                    dest_mip, payload_len, (int)payload_len, payload);
            }
        }
    }
}


/*
Entry point for MIP daemon.
Parses command line arguments.
Validates MIP address (0-254), and prints parsed values if debug mode is activated.
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


    run_daemon(sd_upper, sd_raw, debug);

    return 0;
}