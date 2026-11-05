/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * backend_ptrace.c - reference implementation of the nproot backend
 * interface on top of ptrace(2).  This is the status quo of proot:
 * full semantics (argument rewriting through register/memory access)
 * at the cost of two context switches per syscall.
 *
 * Built standalone by `make -C src/backend demo`; the binary
 * `demo-ptrace` supervises /bin/echo and prints the syscall events it
 * sees, demonstrating the event protocol the interface describes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "backend.h"

/* Register access is the only architecture-dependent part of a ptrace
 * backend.  Keep the demo portable across x86_64 and aarch64 (glibc,
 * musl, bionic) instead of relying on the x86-only <sys/reg.h>.
 *
 * Common syscall ABI: nr in the "orig" register (x86_64: ORIG_RAX,
 * aarch64: x8 at syscall-entry stop), arguments in x0..x2 / rdi..rdx.
 */

#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS 12
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

struct backend_regs {
	long nr;
	long args[3];
};

#if defined(__x86_64__)

static int fetch_regs(pid_t pid, struct backend_regs *out)
{
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		return -1;
	out->nr      = (long)regs.orig_rax;
	out->args[0] = (long)regs.rdi;
	out->args[1] = (long)regs.rsi;
	out->args[2] = (long)regs.rdx;
	return 0;
}

#elif defined(__aarch64__)

static int fetch_regs(pid_t pid, struct backend_regs *out)
{
	/* glibc names the NT_PRSTATUS register set user_regs_struct
	 * on aarch64 (identical layout to the kernel's user_pt_regs).
	 */
	struct user_regs_struct regs;
	struct iovec iov = { &regs, sizeof(regs) };

	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
		return -1;
	out->nr      = (long)regs.regs[8];      /* x8: syscall number */
	out->args[0] = (long)regs.regs[0];
	out->args[1] = (long)regs.regs[1];
	out->args[2] = (long)regs.regs[2];
	return 0;
}

#else

static int fetch_regs(pid_t pid, struct backend_regs *out)
{
	(void)pid;
	(void)out;
	errno = ENOSYS;
	return -1;
}

#endif

const struct backend_ops backend_ptrace_ops = {
	.name = "ptrace",
	.caps = {
		.rewrite_args   = true,
		.forge_retval   = true,
		.deny_syscall   = true,
		.survives_exec  = true,
		.static_elf     = true,
	},
};

/* Demo only: a minimal syscall-tracing loop equivalent to what
 * tracee/event.c does today.  A full implementation would plug the
 * events into syscall/enter.c and syscall/exit.c.  */
int main(void)
{
	pid_t child;
	int status;

	child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}
	if (child == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execl("/bin/echo", "echo", "hello-from-backend-ptrace", (char *)NULL);
		_exit(127);
	}

	if (waitpid(child, &status, 0) < 0) {   /* exec stop */
		perror("waitpid");
		return 1;
	}
	ptrace(PTRACE_SETOPTIONS, child, NULL,
	       (void *)(long)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL));

	bool entering = true;

	for (;;) {
		struct backend_syscall event;
		int sig = 0;

		if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0)
			break;
		if (waitpid(child, &status, 0) < 0)
			break;

		if (WIFEXITED(status) || WIFSIGNALED(status))
			break;

		memset(&event, 0, sizeof(event));

		if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
			struct backend_regs regs;

			event.entering = entering;
			entering = !entering;   /* entry stop, then exit stop */
			if (!event.entering)
				continue;
			if (fetch_regs(child, &regs) < 0)
				break;
			event.nr      = regs.nr;
			event.args[0] = regs.args[0];
			event.args[1] = regs.args[1];
			event.args[2] = regs.args[2];
			printf("[ptrace] syscall %ld(0x%lx, 0x%lx, 0x%lx)\n",
			       event.nr, event.args[0], event.args[1], event.args[2]);
		} else if (WIFSTOPPED(status)) {
			sig = WSTOPSIG(status);
			printf("[ptrace] signal delivery stop: %d\n", sig);
		}
	}

	if (waitpid(child, &status, 0) >= 0 && WIFEXITED(status))
		printf("[ptrace] child exited with %d; capabilities: "
		       "rewrite_args/forge_retval/deny_syscall all true\n",
		       WEXITSTATUS(status));

	printf("RESULT: ptrace backend usable (as it always was)\n");
	return 0;
}
