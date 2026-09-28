#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mip.h"

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-h] [-d] <socket_upper> <MIP address>\n", prog);
}

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

    return 0;
}