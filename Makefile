# cross-compile module makefile

ifneq ($(KERNELRELEASE),)
    obj-m := cmpc.o
else
        PWD := $(shell pwd)

default:
ifeq ($(strip $(KERNELDIR)),)
	$(error "KERNELDIR is undefined!")
else
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif


clean:
	rm -rf *~ *.ko *.o *.mod.c modules.order Module.symvers .cmpc* .tmp_versions

endif


