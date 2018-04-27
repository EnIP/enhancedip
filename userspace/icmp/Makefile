#CC=arm-linux-gnueabi-gcc
CC:=gcc
RM:=rm
CFLAGS := -g #-Wall -Werror

all: ping_and_traceroute

ping_and_traceroute:
	#
	# good code
	#
	$(CC) $(CFLAGS) -o e_ping ping.c hexdump.c oping.c
	cp e_ping experiments/icmp/
	$(CC) $(CFLAGS) -o e_tcpping tcp_ping.c hexdump.c lib.c tcp.c udp.c checksum.c -lresolv -lpcap -lpthread
	cp e_tcpping experiments/tcp/
	$(CC) $(CFLAGS) -o e_traceroute traceroute.c hexdump.c icmp.c lib.c checksum.c -lresolv
	$(CC) $(CFLAGS) -o e_icmpd icmpd.c hexdump.c opong.c -lpcap
	#
	# experimental code
	#
	$(CC) $(CFLAGS) -o e_measure measure.c hexdump.c oping.c
	#
	#$(CC) $(CFLAGS) -c tcp.c
	#$(CC) $(CFLAGS) -o e_tcp_traceroute tcp_traceroute.c hexdump.c lib.c checksum.c tcp.c -lresolv -lpcap -lpthread

	#$(CC) -g -o findip findip.c hexdump.c oping.c

install:
	cp e_measure /usr/sbin/e_measure
	cp e_traceroute /usr/sbin/
	cp e_ping /usr/sbin/
	cp e_tcpping /usr/sbin/

clean:
	$(RM) -f *.o e_icmpd e_tcpping e_measure testtime experiments/icmp/e_ping e_ping experiments/tcp/e_tcp_ping e_trace_route findip tags

