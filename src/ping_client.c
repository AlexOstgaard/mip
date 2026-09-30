#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define MAX_SDU_SIZE 1496
#define MAX_MESSAGE_SIZE (MAX_SDU_SIZE + 1)
#define TIMEOUT_MS 1000

/**
 * Print program usage information.
 *
 * prog: Name used to invoke this program.
 *
 * Returns nothing.
 */
static void print_usage(const char *prog)
{
    printf("Usage: %s [-h] <socket_lower> <message> <destination_host>\n",
           prog);
    printf("  -h                  Print this help message and exit\n");
    printf("  socket_lower        UNIX socket used by mipd\n");
    printf("  message             Text to send in the PING message\n");
    printf("  destination_host    Destination MIP address\n");
}

/**
 * Convert a decimal MIP address string to an unsigned 8-bit address.
 *
 * string: Decimal string representing a MIP address.
 * address: Output location for the converted address.
 *
 * Returns 0 on success, or -1 if the value is invalid.
 */
static int parse_mip_address(const char *string, uint8_t *address)
{
    char *end;
    long value;

    errno = 0;
    value = strtol(string, &end, 10);

    if (errno != 0 || *string == '\0' || *end != '\0' ||
        value < 0 || value > 255) {
        return -1;
    }

    *address = (uint8_t)value;
    return 0;
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
 * Remove trailing zero-byte MIP padding from a payload.
 *
 * payload: Pointer to the payload.
 * length: Number of bytes in the payload.
 *
 * Returns the number of bytes excluding trailing zero padding.
 */
static size_t remove_padding(const uint8_t *payload, size_t length)
{
    while (length > 0 && payload[length - 1] == '\0') {
        length--;
    }

    return length;
}

/**
 * Calculate elapsed time in milliseconds.
 *
 * start: Timestamp captured before transmission.
 * end: Timestamp captured after reception.
 *
 * Returns elapsed time in milliseconds.
 */
static double elapsed_ms(const struct timespec *start,
                         const struct timespec *end)
{
    time_t seconds = end->tv_sec - start->tv_sec;
    long nanoseconds = end->tv_nsec - start->tv_nsec;

    return (double)seconds * 1000.0 + (double)nanoseconds / 1000000.0;
}

/**
 * Send one MIP SDU to mipd.
 *
 * sd: Connected UNIX socket to mipd.
 * destination: MIP address to put first in the UNIX socket message.
 * payload: SDU to send.
 * payload_length: Number of bytes in payload.
 *
 * Returns 0 on success, or -1 on error.
 */
static int send_to_mipd(int sd, uint8_t destination,
                        const uint8_t *payload, size_t payload_length)
{
    uint8_t message[MAX_MESSAGE_SIZE];
    ssize_t sent;
    size_t total_length;

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
 * Wait for the expected PONG reply for at most one second.
 *
 * sd: Connected UNIX socket to mipd.
 * expected_pong: Exact unpadded PONG payload expected from the server.
 * expected_length: Number of bytes in expected_pong.
 * start: Timestamp from immediately before the request was sent.
 *
 * Returns 0 when the matching PONG is received, 1 on timeout,
 * or -1 on a socket/error condition.
 */
static int wait_for_pong(int sd, const uint8_t *expected_pong,
                         size_t expected_length,
                         const struct timespec *start)
{
    struct pollfd pfd;
    uint8_t message[MAX_MESSAGE_SIZE];

    pfd.fd = sd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    for (;;) {
        int poll_result;
        ssize_t received;
        size_t payload_length;
        size_t unpadded_length;
        struct timespec end;

        poll_result = poll(&pfd, 1, TIMEOUT_MS);

        if (poll_result == 0) {
            return 1;
        }

        if (poll_result == -1) {
            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        if ((pfd.revents & POLLIN) == 0) {
            return -1;
        }

        received = recv(sd, message, sizeof(message), 0);
        if (received == -1) {
            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        if (received <= 1) {
            continue;
        }

        payload_length = (size_t)received - 1;
        unpadded_length = remove_padding(message + 1, payload_length);

        /*
         * Ignore messages that are not the PONG corresponding to our PING.
         */
        if (unpadded_length != expected_length ||
            memcmp(message + 1, expected_pong, expected_length) != 0) {
            continue;
        }

        if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
            return -1;
        }

        printf("PONG received from MIP address %u in %.3f ms\n",
               (unsigned int)message[0], elapsed_ms(start, &end));

        return 0;
    }
}

/**
 * Build and send a PING request, then wait for its matching PONG response.
 *
 * argc: Number of command-line arguments.
 * argv: Command-line argument array.
 *
 * Returns EXIT_SUCCESS after a matching PONG, EXIT_FAILURE on an error
 * or timeout.
 */
int main(int argc, char *argv[])
{
    const char *socket_path;
    const char *user_message;
    uint8_t destination;
    uint8_t ping[MAX_SDU_SIZE];
    uint8_t expected_pong[MAX_SDU_SIZE];
    size_t user_message_length;
    size_t ping_length;
    size_t expected_pong_length;
    int sd;
    int result;
    struct timespec start;

    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if (argc != 4) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    socket_path = argv[1];
    user_message = argv[2];

    if (parse_mip_address(argv[3], &destination) == -1) {
        fprintf(stderr, "Invalid destination MIP address: %s\n", argv[3]);
        return EXIT_FAILURE;
    }

    user_message_length = strlen(user_message);

    /*
     * PING: + user message. Reserve room for possible zero padding.
     */
    if (user_message_length + 5 > MAX_SDU_SIZE - 3) {
        fprintf(stderr, "Message is too long\n");
        return EXIT_FAILURE;
    }

    memcpy(ping, "PING:", 5);
    memcpy(ping + 5, user_message, user_message_length);
    ping_length = user_message_length + 5;

    /*
     * Expected server response is PONG: followed by the complete received
     * PING message, i.e. PONG:PING:<user message>.
     */
    memcpy(expected_pong, "PONG:", 5);
    memcpy(expected_pong + 5, ping, ping_length);
    expected_pong_length = ping_length + 5;

    /*
     * Pad the outgoing MIP SDU to a multiple of four bytes.
     */
    while (ping_length % 4 != 0) {
        ping[ping_length++] = '\0';
    }

    sd = connect_to_mipd(socket_path);
    if (sd == -1) {
        perror("connect to mipd");
        return EXIT_FAILURE;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
        perror("clock_gettime");
        close(sd);
        return EXIT_FAILURE;
    }

    if (send_to_mipd(sd, destination, ping, ping_length) == -1) {
        perror("send PING to mipd");
        close(sd);
        return EXIT_FAILURE;
    }

    printf("Sent Ping to MIP address %u: %s\n",
           (unsigned int)destination, user_message);

    result = wait_for_pong(sd, expected_pong, expected_pong_length, &start);

    if (result == 1) {
        printf("timeout\n");
        close(sd);
        return EXIT_FAILURE;
    }

    if (result == -1) {
        perror("waiting for PONG");
        close(sd);
        return EXIT_FAILURE;
    }

    close(sd);
    return EXIT_SUCCESS;
}
