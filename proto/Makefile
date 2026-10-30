# LD_PRELOAD prototype (route D) of nproot: no-ptrace path translation.
#
#   make                      build libnproot.so + nproot-lite (host libc)
#   make preload/libnproot-musl.so    musl shim build, for Alpine guests
#                             (requires musl-gcc)
#   make check                build and run ./run-tests.sh against a rootfs
#                             (set ROOTFS=/path/to/rootfs, see run-tests.sh)
#   make clean
#
# See README.md for design notes and measured results.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
MUSL_CC ?= musl-gcc

all: preload/libnproot.so launcher/nproot-lite

preload/libnproot.so: preload/nproot_preload.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl

launcher/nproot-lite: launcher/nproot-lite.c
	$(CC) $(CFLAGS) -o $@ $<

# The shim interposes guest libc, so a musl guest needs a musl-built shim.
preload/libnproot-musl.so: preload/nproot_preload.c
	$(MUSL_CC) $(CFLAGS) -fPIC -shared -o $@ $<

check: all
	./run-tests.sh

clean:
	-rm -f preload/libnproot.so libnproot.so launcher/nproot-lite

.PHONY: all check clean
