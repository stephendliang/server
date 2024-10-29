CC = g++

CCFLAGS ?= -Wall -Werror -Wpedantic -Ofast -march=native -D_GNU_SOURCE -luring -std=c++23 -nostdinc++
all_targets = uring_server server2 sqpoll

.PHONY: liburing uring_server server2 sqpoll

all: $(all_targets)

clean:
	rm -f $(all_targets)

liburing:
	+$(MAKE) -C ./liburing

uring_server:
	$(CC) uring_server.cc -o ./uring_server  ${CCFLAGS}
