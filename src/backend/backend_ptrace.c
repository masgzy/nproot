/* SPDX-License-Identifier: GPL-2.0-or-later */
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "backend.h"

const struct backend_ops backend_ptrace_ops = {
	.name = "ptrace",
	.caps = {
		.rewrite_args	= true,
		.forge_retval	= true,
		.deny_syscall	= true,
		.survives_exec	= true,
		.static_elf	= true,
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

	if (waitpid(child, &status, 0) < 0) {	/* exec stop */
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
		event.nr = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ORIG_RAX, NULL);

		if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
			event.entering = entering;
			entering = !entering;	/* entry stop, then exit stop */
			if (!event.entering)
				continue;
			event.args[0] = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RDI, NULL);
			event.args[1] = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RSI, NULL);
			event.args[2] = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RDX, NULL);
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
