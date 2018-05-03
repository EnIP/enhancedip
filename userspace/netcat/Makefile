CC=gcc
RM=rm

all: netcat

netcat:
	$(CC) -Wall -o e_netcat netcat.c -I ../include/

install:
	cp e_netcat /usr/sbin/e_netcat

clean:
	$(RM) -f e_netcat *.o
