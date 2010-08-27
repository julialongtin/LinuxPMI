TARGETS=forker harness

CC=gcc
CFLAGS=-Wall



all: $(TARGETS)

forker: forker.c tester.h
	$(CC) $(CFLAGS) forker.c -o forker

harness: harness.c tester.h
	$(CC) $(CFLAGS) harness.c -o harness


clean: 
	rm -f $(TARGETS)
