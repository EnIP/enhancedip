obj-m += eipnat.o
#eipnat-objs := eipnat_utils.o eipnat_mod.o
eipnat-objs := eipnat_mod.o

#obj-m += eipnat2.o
#eipnat2-objs := eipnat_utils2.o eipnat_mod2.o



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


