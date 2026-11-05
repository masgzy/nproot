# Standalone build for the nproot backend skeletons.
#
#   make            build both demo binaries
#   make demo       the same as `all'
#   make check      build and run the demos
#   make clean
#
# These demos are deliberately NOT linked into the main nproot binary
# yet; they exercise the backend interface standalone so that the
# upstream test suite stays untouched.  See docs/BACKENDS.md.

CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra

DEMOS = demo-ptrace demo-seccomp

all demo: $(DEMOS)

demo-ptrace: backend_ptrace.c backend.h
	$(CC) $(CFLAGS) -I. -o $@ $<

demo-seccomp: backend_seccomp.c backend.h
	$(CC) $(CFLAGS) -I. -o $@ $<

check: all
	@ok=0; \
	./demo-ptrace && ok=$$((ok + 1)) || true; \
	./demo-seccomp && ok=$$((ok + 1)) || true; \
	echo "=== $$ok/2 backend demos passed ==="; \
	test $$ok -eq 2

clean:
	-rm -f $(DEMOS)

.PHONY: all demo check clean
