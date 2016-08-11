QEMU_ROOT := ..
CONFIG_BLKTAP1 := n
-include ../config-host.mak
VPATH=$(SRC_PATH)/tests

CFLAGS := -Wall -Werror -O2 -g -fno-strict-aliasing -ftest-coverage -fprofile-arcs
LDFLAGS=

TESTS=xen-tests

all: $(TESTS)

sep.o: CFLAGS += -D_GNU_SOURCE -DNEED_CPU_H -D__XEN_TOOLS__ -DQEMU_UNITEST -I.. -I../i386-dm -I../hw -I../fpu
sep.o: ../privsep.c

mock.o: mock.h

xen-tests: xen-tests.c ../syslog.c sep.o mock.o
	$(CC) $(CFLAGS) -I.. $(LDFLAGS) -Wl,--wrap,syslog -Wl,--wrap,vsyslog -o $@ $^ -lcheck -ldl

unittests: $(TESTS)
	./xen-tests

clean:
	rm -f *~ *.o $(TESTS)
