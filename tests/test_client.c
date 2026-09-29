#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <socket_path>\n", argv[0]);
        return 1;
    }

    int sd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sd == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, argv[1], sizeof(sa.sun_path) - 1);

    if (connect(sd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("connect");
        return 1;
    }

    uint8_t msg[] = {10, 'H', 'e', 'l', 'l', 'o'};  /* MIP-address 10 + "Hello" */
    send(sd, msg, sizeof(msg), 0);

    close(sd);
    return 0;
}