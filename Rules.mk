INSTALL      = install
INSTALL_DIR  = $(INSTALL) -d -m0755 -p
INSTALL_DATA = $(INSTALL) -m0644 -p
INSTALL_PROG = $(INSTALL) -m0755 -p

CURSES_LIBS = -lncurses
UTIL_LIBS = -lutil
SONAME_LDFLAG = -soname
SHLIB_CFLAGS = -shared

CFLAGS += -D__XEN_TOOLS__

# Enable implicit LFS support *and* explicit LFS names.
CFLAGS  += $(shell getconf LFS_CFLAGS)
CFLAGS  += -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
LDFLAGS += $(shell getconf LFS_LDFLAGS)

CFLAGS += -DNDEBUG
CFLAGS ?= -O2 -fomit-frame-pointer

# CFLAGS settings from xen.hg/tools/Rules.mk
CFLAGS += -std=gnu99
CFLAGS += -mno-tls-direct-seg-refs
CFLAGS += -Wstrict-prototypes
CFLAGS += -Wno-unused-value
CFLAGS += -m64
CFLAGS += -Wdeclaration-after-statement
CFLAGS += -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE

