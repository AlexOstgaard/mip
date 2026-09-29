#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mip.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

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
Accept one connection on the upper-layer UNIX socket and read
a single message from it, for testing the message format.
*/
int handle_upper_layer(int sd_upper){

    int client_sd = accept(sd_upper, NULL, NULL);
    if (client_sd == -1) {
        perror("accept");
        exit(1);
    }

    uint8_t buf[1500];
    ssize_t n = recv(client_sd, buf, sizeof(buf), 0);

    if (n == -1) {
        perror("recv");
    } else if (n == 0) {
        printf("Client closed connection \n");
    } else {
        uint8_t dest_mip = buf[0];
        uint8_t *payload = &buf[1];
        size_t payload_len = n - 1;
        printf("Recieved message from/to MIP-address %u, %zu bytes payload\n", dest_mip, payload_len);
    }
    
    return client_sd;
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

    int client_sd = handle_upper_layer(sd_upper);

    return 0;
}