#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MAX_SDU_SIZE 1496
#define MAX_MESSAGE_SIZE (MAX_SDU_SIZE + 1)

/**
 * Print program usage information.
 *
 * prog: Name used to invoke this program.
 *
 * Returns nothing.
 */
static void print_usage(const char *prog)
{
    printf("Usage: %s [-h] <socket_lower>\n", prog);
    printf("  -h              Print this help message and exit\n");
    printf("  socket_lower    UNIX socket used by mipd\n");
}

/**
 * Connect to the UNIX domain SOCK_SEQPACKET socket created by mipd.
 *
 * path: Filesystem path to the mipd UNIX socket.
 *
 * Returns a connected file descriptor on success, or -1 on error.
 */
static int connect_to_mipd(const char *path)
{
    int sd;
    struct sockaddr_un addr;

    sd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sd == -1) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    if (strlen(path) >= sizeof(addr.sun_path)) {
        errno = ENAMETOOLONG;
        close(sd);
        return -1;
    }

    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(sd);
        return -1;
    }

    return sd;
}

/**
 * Remove zero-byte padding from the end of an SDU.
 *
 * payload: Pointer to the SDU.
 * length: Number of bytes in the SDU.
 *
 * Returns the length after trailing zero bytes have been removed.
 */
static size_t remove_padding(const uint8_t *payload, size_t length)
{
    while (length > 0 && payload[length - 1] == '\0') {
        length--;
    }

    return length;
}

/**
 * Send a payload down to mipd.
 *
 * The first byte sent over the UNIX socket is the MIP destination address.
 * The remaining bytes are the MIP SDU.
 *
 * sd: Connected UNIX socket to mipd.
 * destination: MIP destination address.
 * payload: Payload to send.
 * payload_length: Number of payload bytes.
 *
 * Returns 0 on success, or -1 on error.
 */
static int send_to_mipd(int sd, uint8_t destination,
                        const uint8_t *payload, size_t payload_length)
{
    uint8_t message[MAX_MESSAGE_SIZE];
    size_t total_length;
    ssize_t sent;

    if (payload_length > MAX_SDU_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    message[0] = destination;
    memcpy(message + 1, payload, payload_length);

    total_length = payload_length + 1;

    sent = send(sd, message, total_length, 0);
    if (sent == -1) {
        return -1;
    }

    if ((size_t)sent != total_length) {
        errno = EIO;
        return -1;
    }

    return 0;
}

/**
 * Receive Ping messages from mipd, print them, and reply with PONG.
 *
 * sd: Connected UNIX socket to mipd.
 *
 * Returns 0 if mipd closes the connection, or 1 on an unrecoverable error.
 */
static int receive_and_reply(int sd)
{
    uint8_t message[MAX_MESSAGE_SIZE];
    uint8_t pong[MAX_SDU_SIZE];
    ssize_t received;

    for (;;) {
        uint8_t sender;
        const uint8_t *payload;
        size_t payload_length;
        size_t printable_length;
        size_t pong_length;

        received = recv(sd, message, sizeof(message), 0);

        if (received == -1) {
            if (errno == EINTR) {
                continue;
            }

            perror("recv from mipd");
            return 1;
        }

        if (received == 0) {
            fprintf(stderr, "mipd closed the connection\n");
            return 0;
        }

        if (received < 2) {
            fprintf(stderr, "Ignoring invalid message from mipd\n");
            continue;
        }

        sender = message[0];
        payload = message + 1;
        payload_length = (size_t)received - 1;
        printable_length = remove_padding(payload, payload_length);

        printf("Received Ping from MIP address %u: ",
               (unsigned int)sender);
        fwrite(payload, 1, printable_length, stdout);
        putchar('\n');
        fflush(stdout);

        /*
         * The server responds with PONG followed by exactly the received
         * application message. Thus PING:hello becomes PONG:PING:hello.
         */
        if (printable_length + 5 > sizeof(pong)) {
            fprintf(stderr, "Ping message is too long to reply to\n");
            continue;
        }

        memcpy(pong, "PONG:", 5);
        memcpy(pong + 5, payload, printable_length);
        pong_length = printable_length + 5;

        /*
         * MIP SDU sizes must be divisible by four in this implementation.
         * Add zero padding before passing the SDU down to mipd.
         */
        while (pong_length % 4 != 0) {
            pong[pong_length++] = '\0';
        }

        if (send_to_mipd(sd, sender, pong, pong_length) == -1) {
            perror("send PONG to mipd");
        }
    }
}

/**
 * Connect to mipd, receive PING messages, and send PONG replies.
 *
 * argc: Number of command-line arguments.
 * argv: Command-line argument array.
 *
 * Returns EXIT_SUCCESS on normal termination, otherwise EXIT_FAILURE.
 */
int main(int argc, char *argv[])
{
    int sd;
    int result;

    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if (argc != 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    sd = connect_to_mipd(argv[1]);
    if (sd == -1) {
        perror("connect to mipd");
        return EXIT_FAILURE;
    }

    printf("Ping server connected to %s\n", argv[1]);
    printf("Waiting for Ping messages...\n");

    result = receive_and_reply(sd);
    close(sd);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
