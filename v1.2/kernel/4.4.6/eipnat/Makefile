obj-m += eipnat.o
eipnat-objs := eipnat_mod.o

all:
	echo $(PWD)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	insmod eipnat.ko

uninstall:
	rmmod eipnat


