.PHONY : icmp netcat install clean

all: icmp netcat 

icmp:
	make -C icmp

netcat:
	make -C netcat

install:
	make -C netcat install
	make -C icmp install

clean: 
	make -C icmp clean
	make -C netcat clean


