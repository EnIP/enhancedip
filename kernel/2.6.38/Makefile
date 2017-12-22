
#KERNEL := /usr/src/linux/
KERNEL := /usr/src/linux-2.6.38/

all: donothing

donothing:
	echo "execute make install"

patch:
	#new files
	cp 	eip.h	$(KERNEL)/include/linux/
	cp 	socket-2.6.38/sockaddr_ein.h $(KERNEL)/include/linux/

	#patches
	patch 	$(KERNEL)/include/net/sock.h    patches/sock.h.patch
	patch	$(KERNEL)/net/ipv4/ip_output.c  patches/ip_output.c.patch
	patch	$(KERNEL)/net/ipv4/tcp_ipv4.c   patches/tcp_ipv4.c.patch
	patch	$(KERNEL)/net/ipv4/tcp_output.c patches/tcp_output.c.patch
	patch   $(KERNEL)/net/ipv4/udp.c 	patches/udp.c.patch
	patch	$(KERNEL)/net/ipv4/ip_options.c patches/ip_options.c.patch
	patch	$(KERNEL)/net/ipv4/netfilter/nf_nat_core.c \
	patches/nf_nat_core.c.patch

	#things we couldn't patch cleanly
	cp	socket-2.6.38/socket.c		$(KERNEL)/net/
	


install:
	cp eip.h       $(KERNEL)/include/linux/
	cp sock.h      $(KERNEL)/include/net/
	cp ip_output.c $(KERNEL)/net/ipv4/
	cp tcp_ipv4.c  $(KERNEL)/net/ipv4/
	cp tcp_output.c $(KERNEL)/net/ipv4/
	cp udp.c      $(KERNEL)/net/ipv4/
	cp ip_options.c $(KERNEL)/net/ipv4/
	cp socket-2.6.38-gentoo-r6/sockaddr_ein.h $(KERNEL)/include/linux/
	cp socket-2.6.38-gentoo-r6/socket.c $(KERNEL)/net/
	cp nat/nf_nat_core.c $(KERNEL)/net/ipv4/netfilter/

	
