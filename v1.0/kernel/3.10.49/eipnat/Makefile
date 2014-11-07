OPENWRT = /media/disk2/openwrt/ 

KERNEL = /media/disk2/openwrt/build_dir/target-mips_34kc_uClibc-0.9.33.2/linux-ar71xx_generic/linux-3.10.49/
LD = /media/disk2/openwrt/staging_dir/toolchain-mips_34kc_gcc-4.8-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-uclibc-ld

obj-m += eipnat.o
eipnat-objs := eipnat_mod.o


all:
	make -C ${KERNEL} ARCH="mips" CC=mips-openwrt-linux-uclibc-gcc  M=$(PWD) modules

clean:
	make -C ${KERNEL} CC=mips-openwrt-linux-uclibc-gcc  M=$(PWD) clean
