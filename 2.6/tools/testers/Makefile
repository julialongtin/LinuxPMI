TARGETS=forker harness

CC=gcc
CFLAGS=-Wall



all: $(TARGETS)

forker: forker.c
	$(CC) $(CFLAGS) forker.c -o forker

harness: harness.c
	$(CC) $(CFLAGS) harness.c -o harness


clean: 
	rm -f $(TARGETS)