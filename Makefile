
CCFLAGS ?= -Wall -Ofast -D_GNU_SOURCE -luring
all_targets = io_uring_echo_server

.PHONY: liburing io_uring_echo_server

all: $(all_targets)

clean:
	rm -f $(all_targets)

liburing:
	+$(MAKE) -C ./liburing

io_uring_echo_server:
	$(CC) sqpoll.c -o ./io_uring_echo_server  ${CCFLAGS}
	#$(CC) io_uring_echo_server.c -o ./io_uring_echo_server  ${CCFLAGS}
