# If you want to build outside of the source tree, use the -f option:
#     make -f ${SOMEWHERE}/proot/src/GNUmakefile

# the VPATH variable must point to the actual makefile directory
VPATH := $(dir $(lastword $(MAKEFILE_LIST)))
SRC    = $(dir $(firstword $(MAKEFILE_LIST)))

GIT      = git
RM       = rm
INSTALL  = install
CC       ?= $(CROSS_COMPILE)gcc
LD       = $(CC)
STRIP    ?= $(CROSS_COMPILE)strip
OBJCOPY  ?= $(CROSS_COMPILE)objcopy
OBJDUMP  ?= $(CROSS_COMPILE)objdump

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I. -I$(VPATH)
# Compile-time redirection of the legacy file syscalls (access, pipe,
# rename, mkdir, rmdir, unlink, chmod, symlink) to their *at/modern
# equivalents: Android's app seccomp filter traps the legacy family
# and the static launcher carries no SIGSYS guard.  "override" so a
# CPPFLAGS set on the command line (as the CI does) does not silence
# it; see fileat_wrap.c.  (A link-time --wrap=access was tried first
# and silently failed: ld does not wrap versioned undefined symbols
# like access@GLIBC_2.2.5.)
override CPPFLAGS += -Daccess=nproot_access -Dunlink=nproot_unlink \
	-Drmdir=nproot_rmdir -Dmkdir=nproot_mkdir -Drename=nproot_rename \
	-Dchmod=nproot_chmod -Dsymlink=nproot_symlink -Dpipe=nproot_pipe \
	-Dstat=nproot_stat -Dlstat=nproot_lstat
CFLAGS   += -Wall -Wextra -O2
# Link talloc through this knob, so packagers can swap in a static
# archive instead, e.g.
#     make ... TALLOC_LINK=/path/to/libtalloc.a   (or -l:libtalloc.a)
# A binary linked this way carries talloc inside and needs no
# libtalloc.so.2 at run time; the Android CI builds exactly so,
# since the bionic dynamic linker never searches the executable's
# own directory and a stray .so beside it goes unnoticed.  This
# goes on the LINK rule rather than into LDFLAGS: variables set on
# the make command line silence every makefile append to LDFLAGS,
# and the CI, among others, sets LDFLAGS on the command line.
TALLOC_LINK ?= -ltalloc
LDFLAGS  += -Wl,-z,noexecstack
ifdef PROOT_WITH_LIBANDROID_SHMEM
  CFLAGS += -DWITH_LIBANDROID_SHMEM
  LDFLAGS += -landroid-shmem
endif

OBJECTS += \
	env_sanitize.o          \
	fileat_wrap.o           \
	cli/cli.o               \
	cli/proot.o             \
	cli/note.o              \
	execve/enter.o          \
	execve/exit.o           \
	execve/shebang.o        \
	execve/elf.o            \
	execve/ldso.o           \
	execve/auxv.o           \
	execve/aoxp.o           \
	path/binding.o          \
	path/glue.o             \
	path/canon.o            \
	path/f2fs-bug.o         \
	path/path.o             \
	path/proc.o             \
	path/temp.o             \
	syscall/seccomp.o       \
	syscall/syscall.o       \
	syscall/chain.o         \
	syscall/enter.o         \
	syscall/exit.o          \
	syscall/sysnum.o        \
	syscall/socket.o        \
	syscall/heap.o          \
	syscall/rlimit.o        \
	syscall/pipe_shadow.o   \
	tracee/tracee.o         \
	tracee/mem.o            \
	tracee/reg.o            \
	tracee/event.o          \
	tracee/seccomp.o        \
	tracee/statx.o          \
	ptrace/ptrace.o         \
	ptrace/user.o           \
	ptrace/wait.o           \
	extension/extension.o   \
	extension/ashmem_memfd/ashmem_memfd.o \
	extension/kompat/kompat.o \
	extension/fake_id0/chown.o \
	extension/fake_id0/chroot.o \
	extension/fake_id0/getsockopt.o \
	extension/fake_id0/sendmsg.o \
	extension/fake_id0/socket.o \
	extension/fake_id0/open.o \
	extension/fake_id0/unlink.o \
	extension/fake_id0/rename.o \
	extension/fake_id0/chmod.o \
	extension/fake_id0/utimensat.o \
	extension/fake_id0/access.o \
	extension/fake_id0/exec.o \
	extension/fake_id0/link.o \
	extension/fake_id0/symlink.o \
	extension/fake_id0/mk.o \
	extension/fake_id0/stat.o \
	extension/fake_id0/helper_functions.o \
	extension/fake_id0/fake_id0.o \
	extension/hidden_files/hidden_files.o \
	extension/mountinfo/mountinfo.o \
	extension/port_switch/port_switch.o \
	extension/sysvipc/sysvipc.o \
	extension/sysvipc/sysvipc_msg.o \
	extension/sysvipc/sysvipc_sem.o \
	extension/sysvipc/sysvipc_shm.o \
	extension/link2symlink/link2symlink.o \
	extension/fix_symlink_size/fix_symlink_size.o \
	proto/proto_launch.o

EMBED_SHIM ?=
ifneq ($(EMBED_SHIM),)
ifeq ($(filter glibc musl both,$(EMBED_SHIM)),)
$(error EMBED_SHIM must be glibc, musl, or both)
endif
ifneq ($(filter glibc both,$(EMBED_SHIM)),)
OBJECTS += shim-glibc-embedded.o
endif
ifneq ($(filter musl both,$(EMBED_SHIM)),)
OBJECTS += shim-musl-embedded.o
endif
endif


define define_from_arch.h
$2$1 := $(shell $(CC) $1 -E -dM -DNO_LIBC_HEADER $(SRC)/arch.h | grep -w $2 | cut -f 3 -d ' ')
endef

$(eval $(call define_from_arch.h,,HAS_LOADER_32BIT))
$(eval $(call define_from_arch.h,,HAS_POKEDATA_WORKAROUND))

ifdef PROOT_UNBUNDLE_LOADER
  CFLAGS += "-DPROOT_UNBUNDLE_LOADER=\"$(PROOT_UNBUNDLE_LOADER)\""
nproot: | loader/loader
ifdef HAS_LOADER_32BIT
nproot: | loader/loader-m32
endif
else
  OBJECTS += loader/loader-wrapped.o
ifdef HAS_LOADER_32BIT
  OBJECTS += loader/loader-m32-wrapped.o
endif
endif

ifdef HAS_POKEDATA_WORKAROUND
  OBJECTS += loader/loader-info.o
endif

.DEFAULT_GOAL = nproot
all: nproot

######################################################################
# Beautified output

quiet_GEN = @echo "  GEN        $@"; $(GEN)
quiet_CC  = @echo "  CC $@"; $(CC)
quiet_LD  = @echo "  LD $@"; $(LD)
quiet_INSTALL = @echo "  INSTALL        $?"; $(INSTALL)

V = 0
ifeq ($(V), 0)
    quiet = quiet_
    Q     = @
    silently = >/dev/null 2>&1
else
    quiet = 
    Q     = 
    silently = 
endif

######################################################################
# Auto-configuration

CHECK_VERSION = VERSION=$$($(GIT) describe --tags --dirty --abbrev=8 --always 2>/dev/null); \
		if [ ! -z "$${VERSION}" ]; \
		then printf "\#undef VERSION\n\#define VERSION \"$${VERSION}\"\n"; \
		fi;

CHECK_FEATURES = process_vm seccomp_filter
CHECK_PROGRAMS = $(foreach feature,$(CHECK_FEATURES),.check_$(feature))
CHECK_OBJECTS  = $(foreach feature,$(CHECK_FEATURES),.check_$(feature).o)
CHECK_RESULTS  = $(foreach feature,$(CHECK_FEATURES),.check_$(feature).res)

.SILENT .IGNORE .INTERMEDIATE: $(CHECK_OBJECTS) $(CHECK_PROGRAMS)

.check_%.o: .check_%.c
	-$(COMPILE:echo=false) $(silently)

.check_%: .check_%.o
	-$(LINK:echo=false) $(silently)

.check_%.res: .check_%
	$(Q)if [ -e $< ]; then echo "#define HAVE_$(shell echo $* | tr a-z A-Z)" > $@; else echo "" > $@; fi

build.h: $(CHECK_RESULTS)
	$($(quiet)GEN)
	$(Q)echo "/* This file is auto-generated, edit at your own risk.  */" > $@
	$(Q)echo "#ifndef BUILD_H"      >> $@
	$(Q)echo "#define BUILD_H"      >> $@
	$(Q)sh -c '$(CHECK_VERSION)'    >> $@
	$(Q)cat $^                      >> $@
	$(Q)echo "#endif /* BUILD_H */" >> $@

BUILD_ID_NONE := $(shell printf 'int main(void){return 0;}\n' | $(LD) -xc - -Wl,--build-id=none -o /dev/null >/dev/null 2>&1 && echo ',--build-id=none')

# Android NDK r29+ compatibility
ROSEGMENT := $(shell printf 'int main(void){return 0;}\n' | $(LD) -xc - -Wl,--rosegment -o /dev/null >/dev/null 2>&1 && echo ',--rosegment')

######################################################################
# Build rules

COMPILE = $($(quiet)CC) $(CPPFLAGS) $(CFLAGS) -MD -c $(SRC)$< -o $@
LINK    = $($(quiet)LD) -o $@ $^ $(TALLOC_LINK) $(LDFLAGS)

OBJIFY = $($(quiet)GEN)                                                                 \
	$(OBJCOPY)                                                                      \
		--input-target=binary                                                           \
		--output-target=`env LANG=C $(OBJDUMP) -f cli/cli.o |                           \
			grep 'file format' | awk '{print $$4}'`                         \
		--binary-architecture `env LANG=C $(OBJDUMP) -f cli/cli.o |             \
				grep architecture | cut -f 1 -d , | awk '{print $$2}'`  \
		$< $@

nproot: $(OBJECTS)
	$(LINK)

# Special case to compute which files depend on the auto-generated
# file "build.h".
USE_BUILD_H := $(patsubst $(SRC)%.c,%.o,$(shell egrep -sl 'include[[:space:]]+"build.h"' $(patsubst %.o,$(SRC)%.c,$(OBJECTS))))
$(USE_BUILD_H): build.h

%.o: %.c
	@mkdir -p $(dir $@)
	$(COMPILE)

cli/%-licenses.o: licenses cli/cli.o
	$(OBJIFY)

######################################################################
# Preload shim for the proto backend (built from proto/preload/).
#
# The shim must be built against the GUEST libc family: the glibc
# shim is built with the regular toolchain, the musl shim needs
# MUSL_CC (e.g. musl-gcc).  Embedding is opt-in:
#
#     make EMBED_SHIM=glibc|musl|both
#
# which objcopy-wraps the shim into the binary (_binary_shim_*_start)
# for proto_launch.c to extract into the temporary directory at
# runtime.  Without embedding, the shim is looked up next to the
# binary (<dir>/preload/) or via $NPROOT_SHIM.

SHIM_CFLAGS = -fPIC -shared -O2 -Wall
# The glibc shim additionally patches the guest libc's clone3 into an
# ENOSYS stub (see proto/preload/nproot_preload.c, "third line of
# defense"); the musl shim must not, so the define is per-target.
SHIM_GLIBC_CFLAGS = $(SHIM_CFLAGS) -DNPROOT_PATCH_SYSCALLS=1
SHIM_SRC    = $(SRC)../proto/preload/nproot_preload.c

shim-glibc.so: $(SHIM_SRC)
	@mkdir -p $(dir $@)
	$($(quiet)CC) $(SHIM_GLIBC_CFLAGS) -o $@ $< -ldl

shim-musl.so: $(SHIM_SRC)
ifdef MUSL_CC
	@mkdir -p $(dir $@)
	$(MUSL_CC) $(SHIM_CFLAGS) -o $@ $<
else
	$(error MUSL_CC is not set: the musl shim needs musl-gcc (or equivalent))
endif

shim-glibc-embedded.o: shim-glibc.so cli/cli.o
	$(OBJIFY)

shim-musl-embedded.o: shim-musl.so cli/cli.o
	$(OBJIFY)

######################################################################
# Build rules for the loader

define build_loader
LOADER$1_OBJECTS = loader/loader$1.o loader/assembly$1.o

$(eval $(call define_from_arch.h,$1,LOADER_ARCH_CFLAGS))
$(eval $(call define_from_arch.h,$1,LOADER_ADDRESS))

LOADER_CFLAGS$1  += -fPIC -ffreestanding $(LOADER_ARCH_CFLAGS$1)
LOADER_LDFLAGS$1 += -static -nostdlib -Wl$(BUILD_ID_NONE),-Ttext=$(LOADER_ADDRESS$1)$(ROSEGMENT),-z,noexecstack

loader/loader$1.o: loader/loader.c
	@mkdir -p $$(dir $$@)
	$$(COMPILE) $1 $$(LOADER_CFLAGS$1)

loader/assembly$1.o: loader/assembly.S
	@mkdir -p $$(dir $$@)
	$$(COMPILE) $1 $$(LOADER_CFLAGS$1)

loader/loader$1: $$(LOADER$1_OBJECTS)
	$$($$(quiet)LD) $1 -o $$@ $$^ $$(LOADER_LDFLAGS$1)

.INTERMEDIATE: loader$1.exe
loader$1.exe: loader/loader$1
	$$(Q)cp $$< $$@
	$$(Q)$(STRIP) $$@

loader/loader$1-wrapped.o: loader$1.exe cli/cli.o
	$$(OBJIFY)
endef

$(eval $(build_loader))

ifdef HAS_LOADER_32BIT
$(eval $(call build_loader,-m32))
endif

loader/loader-info.c: loader/loader
	readelf -s $< | awk -f loader/loader-info.awk > $@

######################################################################
# Dependencies

.DELETE_ON_ERROR:
$(OBJECTS) $(LOADER_OBJECTS) $(LOADER-m32_OBJECTS): $(firstword $(MAKEFILE_LIST))

DEPS = $(OBJECTS:.o=.d) $(LOADER_OBJECTS:.o=.d) $(LOADER-m32_OBJECTS:.o=.d) $(CHECK_OBJECTS:.o=.d)
-include $(DEPS)

######################################################################
# PHONY targets

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: clean distclean install uninstall
clean distclean:
	-$(RM) -f $(CHECK_OBJECTS) $(CHECK_PROGRAMS) $(CHECK_RESULTS) $(OBJECTS) $(LOADER_OBJECTS) $(LOADER-m32_OBJECTS) nproot loader/loader loader/loader-m32 shim-glibc.so shim-musl.so $(DEPS) build.h licenses

install: nproot
	$($(quiet)INSTALL) -D $< $(DESTDIR)$(BINDIR)/$<
ifdef PROOT_UNBUNDLE_LOADER
	$(INSTALL) -D loader/loader $(PROOT_UNBUNDLE_LOADER)/loader
ifdef HAS_LOADER_32BIT
	$(INSTALL) -D loader/loader-m32 $(PROOT_UNBUNDLE_LOADER)/loader32
endif
endif

uninstall:
	-$(RM) -f $(DESTDIR)$(BINDIR)/nproot
ifdef PROOT_UNBUNDLE_LOADER
	$(INSTALL) -D loader/loader $(PROOT_UNBUNDLE_LOADER)/loader
ifdef HAS_LOADER_32BIT
	$(INSTALL) -D loader/loader-m32 $(PROOT_UNBUNDLE_LOADER)/loader32
endif
endif
