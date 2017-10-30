CC=g++

#CFLAGS=-Wall -W -g -Werror
CFLAGS=-W -g


all: client server

client: client.c
	$(CC) client.c raw.c iterator.c linkedlist.c $(CFLAGS) -o client

server: server.c
	$(CC) server.c iterator.c linkedlist.c $(CFLAGS) -o server

clean:
	rm -f client server *.o
	rm -f client.c

