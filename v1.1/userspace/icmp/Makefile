#CC=arm-linux-gnueabi-gcc
CC=gcc
RM=rm

all: ping

ping:
	$(CC) -g -o ping ping.c hexdump.c oping.c
	$(CC) -g -o traceroute traceroute.c hexdump.c icmp.c lib.c checksum.c -lresolv
	$(CC) -g -o measure measure.c hexdump.c oping.c
	$(CC) -g -o etraceroute etraceroute.c hexdump.c lib.c tcp.c udp.c checksum.c -lresolv -lpcap -lpthread

old:
	$(CC) -g -o findip findip.c hexdump.c oping.c
	$(CC) -o icmpd icmpd.c hexdump.c opong.c -lpcap

clean:
	$(RM) -f *.o etraceroute measure testtime ping traceroute findip tags

