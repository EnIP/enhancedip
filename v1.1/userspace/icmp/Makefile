#CC=arm-linux-gnueabi-gcc
CC=gcc
RM=rm

all: ping_and_traceroute

ping_and_traceroute:
	#
	# good code
	#
	$(CC) -g -o eping ping.c hexdump.c oping.c
	cp eping experiments/icmp/
	$(CC) -g -o tcp_ping tcp_ping.c hexdump.c lib.c tcp.c udp.c checksum.c -lresolv -lpcap -lpthread
	cp tcp_ping experiments/tcp/
	$(CC) -g -o traceroute traceroute.c hexdump.c icmp.c lib.c checksum.c -lresolv
	
	#
	# experimental code
	#
	$(CC) -g -o measure measure.c hexdump.c oping.c
	#

old:
	$(CC) -g -o findip findip.c hexdump.c oping.c
	$(CC) -o icmpd icmpd.c hexdump.c opong.c -lpcap

clean:
	$(RM) -f *.o tcp_ping measure testtime experiments/icmp/eping eping experiments/tcp/tcp_ping traceroute findip tags

