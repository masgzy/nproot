/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * backend.h - pluggable process-interception interface for nproot.
 *
 * PRoot's core hard-wires ptrace(2): the event loop, the register
 * access and the memory access all assume a tracer/tracee pair.  To
 * make a ptrace-free nproot possible without rewriting the whole
 * tree, the interception mechanism is being factored into small
 * "backends" behind this interface:
 *
 *   backend_ptrace.c   the status quo: full proot semantics through
 *                      ptrace(2).  Kept as the compatibility backend
 *                      and as the reference for what the interface
 *                      must express.
 *
 *   backend_seccomp.c  seccomp user-notify based (no ptrace): works
 *                      on Linux >= 5.0, can forge return values and
 *                      deny syscalls, but CANNOT rewrite syscall
 *                      arguments -- path translation therefore needs
 *                      a different route (see docs/BACKENDS.md).
 *
 * This is a skeleton: v0 of the interface, exercised by the two demo
 * binaries built from this directory (`make -C src/backend demo`).
 * Wiring it into tracee/event.c is phase 2 of docs/BACKENDS.md.
 */
#ifndef NPROOT_BACKEND_H
#define NPROOT_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* A syscall event as observed on the guest.  */
struct backend_syscall {
        long            nr;             /* syscall number                       */
        unsigned long   args[6];        /* raw arguments                        */
        unsigned long   retval;         /* on exit events                       */
        bool            entering;       /* true before, false after the syscall */
};

/*
 * Backend capability matrix (v0).  A backend must honestly declare
 * what it can do; nproot refuses to start with a backend that cannot
 * satisfy the requested extensions.
 */
struct backend_caps {
        bool    rewrite_args;   /* modify syscall arguments (path translation) */
        bool    forge_retval;   /* replace the syscall return value          */
        bool    deny_syscall;   /* make a syscall fail with a chosen errno   */
        bool    survives_exec;  /* interception persists across guest execve */
        bool    static_elf;     /* intercepts statically linked guests too   */
};

struct backend_ops {
        const char             *name;
        struct backend_caps     caps;

        /*
         * Start supervising `pid`.  For ptrace this attaches to the
         * tracee; for seccomp it installs the user-notify filter into
         * the (freshly forked) child before it execs the guest.
         */
        int     (*attach)(void *ctx, pid_t pid);

        /*
         * Block until the guest hits the next event.  Returns 0 and
         * fills `event`, or -1 with errno set (guest died, ...).
         */
        int     (*wait_event)(void *ctx, struct backend_syscall *event);

        /* Reply to the event: run the syscall as-is (-1), fail it with
         * `error`, or substitute `retval`.  Only meaningful on entry
         * events and only within the backend's capabilities.           */
        int     (*resume)(void *ctx, const struct backend_syscall *event,
                          int action, long error, long retval);

        /* Guest register set (whole set, no partial updates in v0).  */
        int     (*get_regs)(void *ctx, pid_t pid, void *regs, size_t size);
        int     (*set_regs)(void *ctx, pid_t pid, const void *regs, size_t size);

        /* Guest memory access (used by path translation and the loader). */
        ssize_t (*read_mem)(void *ctx, pid_t pid, unsigned long addr,
                            void *buf, size_t size);
        ssize_t (*write_mem)(void *ctx, pid_t pid, unsigned long addr,
                             const void *buf, size_t size);

        void    (*detach)(void *ctx, pid_t pid);
};

/* resume() actions */
enum {
        BACKEND_RUN = 0,        /* execute the syscall untouched        */
        BACKEND_FAIL,           /* fail it with the given errno         */
        BACKEND_FAKE_RET,       /* skip it, pretend `retval` returned   */
};

extern const struct backend_ops backend_ptrace_ops;
extern const struct backend_ops backend_seccomp_ops;

#endif /* NPROOT_BACKEND_H */
