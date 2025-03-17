# =====================================
# Kernel Module Build Configuration
# =====================================

obj-m := sniffer_char.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# =====================================
# Build Targets
# =====================================

all:
	@echo "Building kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	@echo "Cleaning up..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f sniffer_user

load:
	@echo "Loading kernel module..."
	sudo insmod sniffer_char.ko || dmesg | tail -20

unload:
	@echo "Unloading kernel module..."
	sudo rmmod sniffer_char || true

device:
	@echo "Creating device file..."
	# Extract major number from dmesg since grep from /proc/devices may fail
	MAJOR=$$(dmesg | grep 'sniffer: Device registered' | tail -1 | awk '{print $$NF}'); \
	if [ -n "$$MAJOR" ]; then \
		sudo mknod /dev/sniffer c $$MAJOR 0; \
		sudo chmod 666 /dev/sniffer; \
		echo "Device created with major number $$MAJOR"; \
	else \
		echo "Failed to extract major number from dmesg"; \
	fi

user:
	@echo "Building user-space program..."
	gcc -o sniffer_user sniffer_user.c

run:
	@echo "Running user program..."
	./sniffer_user 1

install:
	@echo "Installing kernel module..."
	sudo insmod sniffer_char.ko
	@echo "Creating device file..."
	MAJOR=$$(dmesg | grep 'sniffer: Device registered' | tail -1 | awk '{print $$NF}'); \
	if [ -n "$$MAJOR" ]; then \
		sudo mknod /dev/sniffer c $$MAJOR 0; \
		sudo chmod 666 /dev/sniffer; \
	else \
		echo "Failed to extract major number"; \
	fi

remove:
	@echo "Removing kernel module and device file..."
	sudo rmmod sniffer_char || true
	sudo rm -f /dev/sniffer
