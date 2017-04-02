obj-m += eip-icmp.o

eip-icmp-objs := eip-icmp_mod.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	insmod eip-icmp.ko 

uninstall:
	rmmod eip-icmp


