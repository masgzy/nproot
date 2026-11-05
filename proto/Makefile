# LD_PRELOAD prototype (route D) of nproot: no-ptrace path translation.
#
#   make                      build libnproot.so + nproot-lite (host libc)
#   make preload/libnproot-musl.so    musl shim build, for Alpine guests
#                             (requires musl-gcc)
#   make check                build and run ./run-tests.sh against a rootfs
#                             (set ROOTFS=/path/to/rootfs, see run-tests.sh)
#   make android              cross-build the aarch64 Android artifacts
#                             into bin/aarch64/ (requires zig, see ANDROID.md)
#   make clean
#
# See README.md for design notes and measured results.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
MUSL_CC ?= musl-gcc
ZIG     ?= zig
# 16 KiB max-page-size keeps the aarch64 artifacts loadable on both
# 4K and 16K page Android devices.
ZFLAGS  ?= -O2 -Wall -Wextra -s -Wl,-z,max-page-size=16384 -Wl,-z,noexecstack

all: preload/libnproot.so launcher/nproot-lite

preload/libnproot.so: preload/nproot_preload.c
	$(CC) $(CFLAGS) -fPIC -shared -DNPROOT_PATCH_SYSCALLS=1 -o $@ $< -ldl

launcher/nproot-lite: launcher/nproot-lite.c
	$(CC) $(CFLAGS) -o $@ $<

# The shim interposes guest libc, so a musl guest needs a musl-built shim.
preload/libnproot-musl.so: preload/nproot_preload.c
	$(MUSL_CC) $(CFLAGS) -fPIC -shared -o $@ $<

check: all
	./run-tests.sh

# Cross-build for aarch64 Android: a static-musl launcher plus one shim
# per guest libc family.  zig cc bundles both sysroots, so neither the
# NDK nor musl-gcc is needed.  See ANDROID.md for the device-side usage.
android:
	mkdir -p bin/aarch64/preload
	$(ZIG) cc -target aarch64-linux-musl $(ZFLAGS) \
	    -o bin/aarch64/nproot-lite launcher/nproot-lite.c
	$(ZIG) cc -target aarch64-linux-gnu $(ZFLAGS) -fPIC -shared \
	    -DNPROOT_PATCH_SYSCALLS=1 \
	    -o bin/aarch64/preload/libnproot.so preload/nproot_preload.c -ldl
	$(ZIG) cc -target aarch64-linux-musl -dynamic $(ZFLAGS) -fPIC -shared \
	    -o bin/aarch64/preload/libnproot-musl.so preload/nproot_preload.c -ldl
	$(ZIG) cc -target aarch64-linux-musl $(ZFLAGS) -static \
	    -o bin/aarch64/host-census census/host_census.c

# Same trio for x86_64 Android (Termux on an x86_64 emulator/AVD):
# the AVD CI job ships bin/x86_64 into the emulator's Termux home.
android-x86_64:
	mkdir -p bin/x86_64/preload
	$(ZIG) cc -target x86_64-linux-musl $(ZFLAGS) \
	    -o bin/x86_64/nproot-lite launcher/nproot-lite.c
	$(ZIG) cc -target x86_64-linux-gnu $(ZFLAGS) -fPIC -shared \
	    -DNPROOT_PATCH_SYSCALLS=1 \
	    -o bin/x86_64/preload/libnproot.so preload/nproot_preload.c -ldl
	$(ZIG) cc -target x86_64-linux-musl -dynamic $(ZFLAGS) -fPIC -shared \
	    -o bin/x86_64/preload/libnproot-musl.so preload/nproot_preload.c -ldl
	$(ZIG) cc -target x86_64-linux-musl $(ZFLAGS) -static \
	    -o bin/x86_64/host-census census/host_census.c

clean:
	-rm -f preload/libnproot.so libnproot.so launcher/nproot-lite
	-rm -rf bin

.PHONY: all check android clean
