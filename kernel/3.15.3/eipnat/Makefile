obj-m += eipnat.o
eipnat-objs := eipnat_mod.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cp eipnat.ko ..
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f ../eipnat.ko

install:
	insmod eipnat.ko

uninstall:
	rmmod eipnat


