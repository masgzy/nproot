# Feasibility probes for the nproot no-ptrace backends.
#
#   make            build both probes
#   make check      build and run them, reporting a summary
#   make clean
#
# Each probe exits 0 when the mechanism it tests is usable on the
# running kernel.  See README.md for how the results map onto the
# backend decision in ../docs/BACKENDS.md.

CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra

PROBES = unotify-probe trap-probe

all: $(PROBES)

unotify-probe: unotify-probe.c
	$(CC) $(CFLAGS) -o $@ $<

trap-probe: trap-probe.c
	$(CC) $(CFLAGS) -o $@ $<

check: all
	@echo "=== kernel: $$(uname -r) ($$(uname -m)) ==="
	@ok=0; \
	./unotify-probe && ok=$$((ok + 1)) || true; \
	./trap-probe && ok=$$((ok + 1)) || true; \
	echo "=== $$ok/2 probes passed ==="; \
	test $$ok -eq 2

clean:
	-rm -f $(PROBES)

.PHONY: all check clean
