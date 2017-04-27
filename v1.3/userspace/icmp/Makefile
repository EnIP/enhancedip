#CC=arm-linux-gnueabi-gcc
CC=gcc
RM=rm

all: ping_and_traceroute

ping_and_traceroute:
	#
	# good code
	#
	$(CC) -g -o e_ping ping.c hexdump.c oping.c
	cp e_ping experiments/icmp/
	$(CC) -g -o e_tcpping tcp_ping.c hexdump.c lib.c tcp.c udp.c checksum.c -lresolv -lpcap -lpthread
	cp e_tcpping experiments/tcp/
	$(CC) -g -o e_traceroute traceroute.c hexdump.c icmp.c lib.c checksum.c -lresolv

	$(CC) -o icmpd icmpd.c hexdump.c opong.c -lpcap
	
	#
	# experimental code
	#
	$(CC) -g -o e_measure measure.c hexdump.c oping.c
	#

old:
	$(CC) -g -o findip findip.c hexdump.c oping.c

install:
	cp e_measure /usr/sbin/e_measure
	cp e_traceroute /usr/sbin/
	cp e_ping /usr/sbin/
	cp e_tcpping /usr/sbin/

clean:
	$(RM) -f *.o tcp_ping measure testtime experiments/icmp/eping eping experiments/tcp/tcp_ping traceroute findip tags

