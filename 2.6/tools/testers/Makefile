TARGETS=forker harness

CC=gcc
CFLAGS=-Wall

HEADERS=tester.h

all: $(TARGETS)

forker: forker.c $(HEADERS)
	$(CC) $(CFLAGS) forker.c -o forker

harness: harness.c $(HEADERS)
	$(CC) $(CFLAGS) harness.c -o harness


clean: 
	rm -f $(TARGETS)
