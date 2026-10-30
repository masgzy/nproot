/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * backend_seccomp.c - seccomp user-notify backend skeleton (no ptrace).
 *
 * Demonstrates the supervision loop of a user-notify backend:
 *
 *   - a filter hands selected syscalls to a listener fd owned by the
 *     nproot supervisor process (survives execve, covers static ELF);
 *   - the supervisor can RUN, FAIL or FAKE_RET the syscall, but it
 *     CANNOT rewrite syscall arguments (no args field in
 *     seccomp_notif_resp, and remote writes would be TOCTOU-unsafe).
 *
 * Consequently this backend can implement fake_id0-like extensions
 * (faking uid/gid syscalls) and deny-paths sandboxes out of the box,
 * while proot's signature path translation needs the trap-route or
 * the LD_PRELOAD route -- see docs/BACKENDS.md for the full picture.
 *
 * Built standalone by `make -C src/backend demo`; the binary
 * `demo-seccomp` forges the child's getuid() to 4242.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "backend.h"

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF			0x7fc00000U
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV	_IOWR('!', 0, struct seccomp_notif)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_SEND
#define SECCOMP_IOCTL_NOTIF_SEND	_IOWR('!', 1, struct seccomp_notif_resp)
#endif

const struct backend_ops backend_seccomp_ops = {
	.name = "seccomp-unotify",
	.caps = {
		.rewrite_args	= false,	/* the fundamental limit */
		.forge_retval	= true,
		.deny_syscall	= true,
		.survives_exec	= true,
		.static_elf	= true,
	},
};

#define FORGED_UID 4242

/* Hand every getuid-family syscall to the supervisor, allow the rest.
 * A production backend would trap the path-taking syscalls it can
 * serve and -- importantly -- keep the trap set minimal, because
 * every trapped syscall pays two context switches.  */
static int install_listener_filter(int *listener)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -1;
	*listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			    SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	return *listener < 0 ? -1 : 0;
}

int main(void)
{
	struct seccomp_notif req;
	struct seccomp_notif_resp resp;
	int listener, status;
	pid_t child;

	/* attach(): in the unotify model the filter lives in the guest,
	 * so it is installed before the guest code ever runs and is
	 * inherited across fork(2) and execve(2) automatically --
	 * no re-attach bookkeeping like ptrace needs.  */
	if (install_listener_filter(&listener) < 0) {
		perror("seccomp(SECCOMP_SET_MODE_FILTER)");
		fprintf(stderr, "user-notify needs Linux >= 5.0\n");
		return 1;
	}
	printf("[seccomp] filter installed, listener fd = %d "
	       "(survives execve, covers static ELF)\n", listener);

	child = fork();
	if (child == 0) {
		uid_t uid = getuid();	/* the single trapped syscall */
		printf("[child] getuid() -> %d (forged by the supervisor)\n",
		       uid);
		fflush(stdout);
		_exit(uid == FORGED_UID ? 0 : 2);
	}

	/* wait_event() + resume(): the supervision loop.  */
	memset(&req, 0, sizeof(req));
	if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
		perror("ioctl(NOTIF_RECV)");
		return 1;
	}
	printf("[supervisor] intercepted syscall %llu from pid %d\n",
	       (unsigned long long)req.data.nr, req.pid);

	memset(&resp, 0, sizeof(resp));
	resp.id = req.id;
	resp.val = FORGED_UID;		/* BACKEND_FAKE_RET */
	resp.error = 0;
	resp.flags = 0;
	if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
		perror("ioctl(NOTIF_SEND)");
		return 1;
	}

	if (waitpid(child, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("[seccomp] return-value forged, zero ptrace used\n");
		printf("RESULT: unotify backend skeleton works; note its hard "
		       "limit: syscall arguments cannot be rewritten here\n");
		return 0;
	}
	fprintf(stderr, "FAIL: child status 0x%x\n", status);
	return 1;
}
