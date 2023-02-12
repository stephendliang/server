CCFLAGS ?= -Wall -Ofast -D_GNU_SOURCE -luring
all_targets = io_uring_echo_server

.PHONY: liburing sqpoll io_uring_echo_server

all: $(all_targets)

clean:
	rm -f $(all_targets)

liburing:
	+$(MAKE) -C ./liburing

sqpoll:
	$(CC) sqpoll.c -o ./sqpoll  ${CCFLAGS}

io_uring_echo_server:
	$(CC) io_uring_echo_server.c -o ./io_uring_echo_server  ${CCFLAGS}
