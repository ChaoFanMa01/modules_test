ifneq ($(KERNELRELEASE),)
	obj-m := filter.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

.PHONY: clean

clean:
	rm filter.mod.* filter.o modules.order filter.ko Module.symvers
