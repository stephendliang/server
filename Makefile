CCFLAGS ?= -Wall -Werror -Wpedantic -Ofast -march=native -D_GNU_SOURCE -luring -std=c++23
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


# Yes, it is possible, at least if you are using Visual Studio C++ or g++.

Compiler Options

If you use Visual Studio C++, lookup the option /X

If you use g++, lookup the option -nostdinc++.

Linker Options

If you use Visual Studio C++, lookup the option /NODEFAULTLIB.

If you use g++, lookup the option -nostdlib.

Share
Improve this answer
Follow
edited Feb 25, 2021 at 14:40
answered May 8, 2014 at 5:49
R Sahu's user avatar
R Sahu
206k1414 gold badges161161 silver badges281281 bronze badges
1
For the compiler, it is -nostdinc++ for g++ and /X 