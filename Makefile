CC      = gcc
CFLAGS  = -Wall -Wextra -Iinclude -g

SRC     = src
BIN_ALL = mipd ping_server ping_client
BIN_TEST = test_header test_client

all: $(BIN_ALL)

mipd: $(SRC)/mipd.c $(SRC)/mip.c include/mip.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/mipd.c $(SRC)/mip.c

ping_server: $(SRC)/ping_server.c
	$(CC) $(CFLAGS) -o $@ $

ping_client: $(SRC)/ping_client.c
	$(CC) $(CFLAGS) -o $@ $

test_header: tests/test_header.c $(SRC)/mip.c include/mip.h
	$(CC) $(CFLAGS) -o $@ tests/test_header.c $(SRC)/mip.c

test_client: tests/test_client.c
	$(CC) $(CFLAGS) -o $@ tests/test_client.c

clean:
	rm -f $(BIN_ALL) $(BIN_TEST)

.PHONY: all clean