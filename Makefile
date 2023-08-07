CCFLAGS ?= -Wall -Werror -Wpedantic -Ofast -march=native -D_GNU_SOURCE -luring
all_targets = server server2 sqpoll

.PHONY: liburing server server2 sqpoll

all: $(all_targets)

clean:
	rm -f $(all_targets)

liburing:
	+$(MAKE) -C ./liburing

server:
	$(CC) server.c -o ./server  ${CCFLAGS}

server2:
	$(CC) server2.c -o ./server2  ${CCFLAGS}

sqpoll:
	$(CC) sqpoll.c -o ./sqpoll  ${CCFLAGS}

