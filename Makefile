CC=gcc
CFLAGS=-I.
DEPS = dnsmap.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

dnsmap: dnsmap.c dnsmap.h
	gcc -o dnsmap dnsmap.c -I.
