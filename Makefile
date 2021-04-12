ifneq ($(KERNELRELEASE),)
	obj-m := hidden_proc.o
#	CFLAGS_sm3.o+=-DSM3_MACRO -Wno-shift-count-overflow
else
	KERNELDIR ?= /lib/modules/`uname  -r`/build
	PWD := $(shell pwd)
default:
	$(MAKE)  -C $(KERNELDIR) M=$(PWD) modules
clean:
	rm -rf *.ko *.o *.mod *.mod.o *.mod.c *.symvers \.*.cmd .tmp_versions modules.order
endif
