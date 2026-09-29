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
            uint8_t raw_buf[1514];
            ssize_t n = recv(sd_raw, raw_buf, sizeof(raw_buf), 0);
            printf("Received %zd bytes on raw socket\n", n);
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