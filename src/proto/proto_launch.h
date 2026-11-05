/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * proto_launch.h - the LD_PRELOAD (no-ptrace) backend, phase 1 of
 * docs/BACKENDS.md.  The guest is started through its own dynamic
 * loader with the nproot shim preloaded (see proto/preload/); no
 * ptrace(2) involvement at all.
 */
#ifndef PROTO_LAUNCH_H
#define PROTO_LAUNCH_H

#include "tracee/tracee.h"

/**
 * Return NULL when the proto backend can carry the current
 * configuration, otherwise a short human-readable reason why it
 * cannot (the caller decides whether that is an error or a reason to
 * fall back to the ptrace backend).
 */
extern const char *proto_infeasible_reason(const Tracee *tracee);

/**
 * The libc family of the guest loader as probed by the last
 * proto_infeasible_reason() run: "musl", "glibc" or "unknown" (before
 * the first probe).  Reported by the startup banner next to the
 * backend name.
 */
extern const char *proto_guest_libc(void);

/**
 * Run the guest through the proto backend.  This function never
 * returns: on success the process becomes the guest program, on
 * failure it reports the error and exits with 127.
 */
extern void proto_launch(Tracee *tracee, char *const argv[]);

#endif /* PROTO_LAUNCH_H */
