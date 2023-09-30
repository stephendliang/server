CC?=gcc
CFLAGS=-Wall -Werror -Ofast
LDFLAGS=-lm

PROVE?=prove

all:

test: parser.c test.c
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f test

.PHONY: test