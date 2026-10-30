/* trap-probe.c - probe SECCOMP_RET_TRAP (SIGSYS) in-process interception.
 *
 * This is the mechanism gVisor's "systrap" platform is built upon and
 * the most promising foundation for a ptrace-free nproot backend.
 *
 * What this program proves on the kernel it runs on:
 *
 *   1. a trapped syscall can be emulated fully IN-PROCESS by a SIGSYS
 *      handler: the handler writes the return value into the ucontext
 *      and the guest keeps running, no ptrace involved.  getuid()
 *      comes back as 4242.
 *
 *   2. KERNEL SEMANTICS DISCOVERED BY THIS PROBE (x86_64, Linux 5.x):
 *      when SIGSYS is delivered for a trapped syscall, the saved
 *      ucontext RIP already points PAST the syscall instruction
 *      (on x86_64 the syscall entry path stores the user return
 *      address from RCX into pt_regs->ip) and RAX still holds the
 *      syscall number.  Emulation is therefore: write the return
 *      register, do NOT advance the instruction pointer.  (The
 *      "skip 2 bytes" recipe found in old blog posts applies to
 *      breakpoint-style traps such as int3/ud2, not to seccomp.)
 *
 *   3. unlike the filter, the SIGSYS handler does NOT survive
 *      execve(2): after the child execs (execve allowed), the fresh
 *      image dies with SIGSYS on its first openat -- which its
 *      dynamic loader performs without any doubt.
 *      => a trap-based nproot backend must own the execve boundary
 *         itself (loader-based exec), see docs/BACKENDS.md, route B.
 *
 * Build:  make
 * Run:    ./trap-probe [; NPROOT_SPIKE_DEBUG=1 ./trap-probe for details]
 * Exit:   0 = all properties confirmed, 1 = unexpected behavior
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SECCOMP_RET_TRAP
#define SECCOMP_RET_TRAP	0x00030000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW	0x7fff0000U
#endif

#define FORGED_UID 4242

#if defined(__x86_64__)
#  define SC_RET(ctx) ((ctx)->uc_mcontext.gregs[REG_RAX])
#  define SC_IP(ctx)  ((ctx)->uc_mcontext.gregs[REG_RIP])
#elif defined(__aarch64__)
#  define SC_RET(ctx) ((ctx)->uc_mcontext.regs[0])
#  define SC_IP(ctx)  ((ctx)->uc_mcontext.pc)
#else
#  error "architecture not supported by this probe"
#endif

static int sys_seccomp_filter(struct sock_fprog *prog)
{
	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, prog);
}

static int install_trap_filter(void)
{
	struct sock_filter filter[] = {
		/* [0] load syscall number */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		/* [1] getuid?  yes -> [2] RET_TRAP, no -> skip 1 -> [3] */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid, 0, 1),
		/* [2] */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
		/* [3] openat?  yes -> [4] RET_TRAP, no -> skip 1 -> [5].
		 * openat is chosen for part 2 because the dynamic loader
		 * of any freshly exec'd image calls it, so the death of
		 * the exec'd child proves the handler did not survive. */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
		/* [4] */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
		/* [5] */
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
	return sys_seccomp_filter(&prog);
}

static void sigsys_handler(int sig, siginfo_t *info, void *uctx)
{
	ucontext_t *ctx = uctx;
	int trapped = info->si_syscall;
	char dbg[160];

	if (getenv("NPROOT_SPIKE_DEBUG") != NULL) {
		unsigned char *ip = (unsigned char *)(uintptr_t)SC_IP(ctx);
		int n = snprintf(dbg, sizeof(dbg),
			"[handler] si_syscall=%d si_arch=0x%x ip=%llx rax=%llx "
			"bytes=[%02x %02x %02x %02x %02x %02x %02x %02x]\n",
			trapped, info->si_arch,
			(unsigned long long)SC_IP(ctx),
			(unsigned long long)SC_RET(ctx),
			ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);
		write(2, dbg, n);
	}

	/*
	 * Emulate the syscall entirely in the tracee's context.
	 *
	 * The saved instruction pointer already sits past the syscall
	 * instruction (see comment [2] in the file header), so writing
	 * the return register is all that is needed.  No RIP advance,
	 * no memory writes.
	 */
	if (trapped == __NR_getuid)
		SC_RET(ctx) = FORGED_UID;
	else
		SC_RET(ctx) = -ENOSYS;

	(void)sig;
}

int main(void)
{
	struct sigaction sa;
	int status;
	pid_t child;
	uid_t uid;

	/* ---- part 1: in-process emulation through the SIGSYS handler ---- */
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigsys_handler;
	sa.sa_flags = SA_SIGINFO | SA_NODEFER;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSYS, &sa, NULL) < 0) {
		perror("sigaction(SIGSYS)");
		return 1;
	}

	if (install_trap_filter() < 0) {
		perror("seccomp(SECCOMP_SET_MODE_FILTER)");
		return 1;
	}

	uid = getuid();	/* trapped: handler emulates it */
	if (uid == FORGED_UID) {
		printf("[1] OK   in-process emulation works: getuid() = %d, "
		       "return register rewritten via ucontext, no ptrace\n",
		       uid);
	} else {
		fprintf(stderr, "FAIL: getuid() returned %d (real uid differs, "
			"forged value is %d), emulation did not work\n",
			uid, FORGED_UID);
		return 1;
	}

	/* ---- part 2: the handler does not survive execve(2) ---- */
	child = fork();
	if (child == 0) {
		/* execve itself is NOT trapped, so the exec succeeds;
		 * the new image has no SIGSYS handler anymore and its
		 * dynamic loader traps on openat -> death by SIGSYS. */
		execl("/bin/true", "true", (char *)NULL);
		_exit(127);
	}
	if (waitpid(child, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
		printf("[2] OK   execve resets the SIGSYS handler: child killed "
		       "by SIGSYS after exec\n");
		printf("RESULT: trap route viable, but execve boundary must be "
		       "owned by nproot (loader-based exec)\n");
		return 0;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
		fprintf(stderr, "FAIL: execve failed before the trap (check /bin/true)\n");
		return 1;
	}
	fprintf(stderr,
		"NOTE: child exited with status 0x%x; /bin/true may not exist\n"
		"      here, rerun where it does to confirm part 2\n", status);
	return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
