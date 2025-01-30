# Makefile for SHA3 Hash Implementation

CC=gcc
CFLAGS=-Wall -g -I./include

all: a.out

# Rule to build the executable

a.out: 
	$(CC) $(CFLAGS) main.c src/hash.c -o a.out

# Clean rule to remove the compiled files

clean:
	rm -f a.out
