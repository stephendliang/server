CCFLAGS ?= -Wall -Werror -Wpedantic -Ofast -D_GNU_SOURCE -luring
all_targets = io_uring_echo_server server sqpoll

.PHONY: liburing server sqpoll io_uring_echo_server

all: $(all_targets)

clean:
	rm -f $(all_targets)

liburing:
	+$(MAKE) -C ./liburing

server:
	$(CC) server.c -o ./server  ${CCFLAGS}

sqpoll:
	$(CC) sqpoll.c -o ./sqpoll  ${CCFLAGS}

io_uring_echo_server:
	$(CC) io_uring_echo_server.c -o ./io_uring_echo_server  ${CCFLAGS}
