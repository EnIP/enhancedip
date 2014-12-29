CC=gcc
RM=rm

all: lib 

lib:
	$(CC) -o getaddr getaddr.c -Wall

	$(CC) -I ../include -Wall -fPIC -shared -o libshim.so shim.c hexdump.c -ldl

dnsclient:
	$(CC) -o dnsclient client.c

dnsserver:
	$(CC) -o dnsserver userver.c

clean:
	unset LD_PRELOAD
	$(RM) -f *.o *.so 
	$(RM) -f dnsclient dnsserver
	$(RM) -f getaddr


