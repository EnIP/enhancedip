
#Edit the kernel line to point to your kernel source tree.
#Currently, only 4.4.6 is supported.
KERNEL  := /usr/src/linux-4.9.28/

all: donothing

donothing:
	echo "execute 'make patch'"

patch:
	cp 	eip.h		$(KERNEL)/include/linux/
	cp 	sockaddr_ein.h 	$(KERNEL)/include/linux/
	cp	socket.c	$(KERNEL)/net/
	cp      sock.h		$(KERNEL)/include/net/
	cp      ip_output.c     $(KERNEL)/net/ipv4/
	cp      tcp_ipv4.c      $(KERNEL)/net/ipv4/
	cp      tcp_output.c	$(KERNEL)/net/ipv4/
	cp      udp.c           $(KERNEL)/net/ipv4/
	cp      ip_options.c    $(KERNEL)/net/ipv4/
	cp      nat/nf_nat_l3proto_ipv4.c  $(KERNEL)/net/ipv4/netfilter/
	
