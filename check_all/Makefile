ifneq ($(KERNELRELEASE),)
	obj-m := check_all.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

.PHONY: clean

clean:
	rm check_all.mod.* check_all.o modules.order check_all.ko Module.symvers
