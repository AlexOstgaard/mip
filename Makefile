CC      = gcc
CFLAGS  = -Wall -Wextra -Iinclude -g

SRC     = src
BIN_ALL = mipd ping_server ping_client
BIN_TEST = test_header test_client test_arp

all: $(BIN_ALL)

mipd: $(SRC)/mipd.c $(SRC)/mip.c $(SRC)/mip_arp.c include/mip.h include/mip_arp.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/mipd.c $(SRC)/mip.c $(SRC)/mip_arp.c

ping_server: $(SRC)/ping_server.c
	$(CC) $(CFLAGS) -o $@ $(SRC)/ping_server.c

ping_client: $(SRC)/ping_client.c
	$(CC) $(CFLAGS) -o $@ $(SRC)/ping_client.c

test_header: tests/test_header.c $(SRC)/mip.c include/mip.h
	$(CC) $(CFLAGS) -o $@ tests/test_header.c $(SRC)/mip.c

test_client: tests/test_client.c
	$(CC) $(CFLAGS) -o $@ tests/test_client.c

test_arp: tests/test_arp.c $(SRC)/mip_arp.c include/mip_arp.h
	$(CC) $(CFLAGS) -o $@ tests/test_arp.c $(SRC)/mip_arp.c

clean:
	rm -f $(BIN_ALL) $(BIN_TEST)

.PHONY: all clean