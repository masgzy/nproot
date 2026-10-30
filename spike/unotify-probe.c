/* unotify-probe.c - probe SECCOMP_RET_USER_NOTIF feasibility for nproot.
 *
 * What this program proves on the kernel it runs on:
 *
 *   1. a user-notify seccomp filter can be installed unprivileged
 *      (needs Linux >= 5.0, SECCOMP_FILTER_FLAG_NEW_LISTENER)
 *   2. the supervisor receives notifications and can forge RETURN
 *      VALUES: the child's getuid() comes back as 4242 while no
 *      ptrace(2) is involved at all
 *   3. it documents the hard limitation: syscall ARGUMENTS cannot be
 *      rewritten through the user-notify response, which is exactly
 *      what proot-style path translation needs.  See docs/BACKENDS.md.
 *
 * Build:  make
 * Run:    ./unotify-probe ; echo $?
 * Exit:   0 = unotify fully usable, 1 = not usable on this kernel
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF		0x7fc00000U
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

#define FORGED_UID 4242

static int sys_seccomp(unsigned int op, unsigned int flags, void *uargs)
{
	return syscall(SYS_seccomp, op, flags, uargs);
}

static int install_listener_filter(void)
{
	struct sock_filter filter[] = {
		/* [0] load syscall number */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		/* [1] if nr == __NR_getuid, hand it to the supervisor */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid, 0, 1),
		/* [2] USER_NOTIF: supervisor decides */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* [3] everything else: run normally */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("prctl(PR_SET_NO_NEW_PRIVS)");
		return -1;
	}
	return sys_seccomp(SECCOMP_SET_MODE_FILTER,
			   SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

int main(void)
{
	int listener, status;
	pid_t child;

	listener = install_listener_filter();
	if (listener < 0) {
		fprintf(stderr,
			"FAIL: SECCOMP_FILTER_FLAG_NEW_LISTENER not usable: %s\n"
			"      user-notify needs Linux >= 5.0\n", strerror(errno));
		return 1;
	}
	printf("[1] OK   user-notify filter installed, listener fd = %d\n", listener);

	child = fork();
	if (child == 0) {
		uid_t uid;

		printf("[child] real uid = %d, now calling getuid()\n", geteuid());
		fflush(stdout);
		uid = getuid();	/* this traps into the supervisor */
		printf("[child] getuid() returned %d\n", uid);
		fflush(stdout);
		_exit(uid == FORGED_UID ? 0 : 2);
	}

	for (;;) {
		struct seccomp_notif req;
		struct seccomp_notif_resp resp;

		memset(&req, 0, sizeof(req));
		if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
			if (errno == EINTR)
				continue;
			perror("ioctl(NOTIF_RECV)");
			return 1;
		}
		printf("[supervisor] notification: syscall %llu from pid %d, "
		       "args = [0x%llx, 0x%llx, 0x%llx]\n",
		       (unsigned long long)req.data.nr, req.pid,
		       (unsigned long long)req.data.args[0],
		       (unsigned long long)req.data.args[1],
		       (unsigned long long)req.data.args[2]);

		memset(&resp, 0, sizeof(resp));
		resp.id = req.id;
		resp.val = FORGED_UID;	/* forge the return value */
		resp.error = 0;
		resp.flags = 0;
		if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
			perror("ioctl(NOTIF_SEND)");
			return 1;
		}
		printf("[supervisor] forged return value %d\n", FORGED_UID);
		break;
	}

	if (waitpid(child, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("[2] OK   return-value injection works, zero ptrace involved\n");
		printf("[3] NOTE syscall ARGUMENTS cannot be rewritten via\n"
		       "           seccomp_notif_resp (no args field, TOCTOU-unsafe);\n"
		       "           proot-style path translation needs another route.\n"
		       "           See docs/BACKENDS.md.\n");
		printf("RESULT: unotify usable on this kernel\n");
		return 0;
	}
	fprintf(stderr, "FAIL: child did not observe the forged uid (status 0x%x)\n",
		status);
	return 1;
}
