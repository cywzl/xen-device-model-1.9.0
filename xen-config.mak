QEMU_ROOT ?= ..
XEN_ROOT ?= $(QEMU_ROOT)/../xen-unstable.hg

include ../config-host.mak

TARGET_ARCH=x86_64
TARGET_PATH:=$(SRC_PATH)/$(TARGET_DIRS)
CONFIG_SOFTMMU=yes

CFLAGS += -I$(QEMU_ROOT)/hw

bindir = ${prefix}/lib64/xen/bin
