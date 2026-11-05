/* SPDX-License-Identifier: GPL-3.0-or-later */
/* host_census.c - standalone seccomp filter surveyor.
 *
 * Run it as a plain user process (a Termux shell, an AVD runner) and
 * it sweeps the syscall table the way the preload shim's census does,
 * but WITHOUT any LD_PRELOAD: it is a static executable, so every
 * Android linker namespace accepts it and no libc symbol can go
 * missing.  It answers the question a silent death poses: which
 * syscalls does the filter this process inherited actually block, and
 * are those blocks catchable TRAPs or uncatchable KILLs?
 *
 * For every syscall number it forks a disposable child that issues
 * the syscall with zeroed arguments -- first with a SIGSYS guard
 * armed, then (if it survived) bare.  The two outcomes classify each
 * number:
 *
 *   died even with the guard  ->  RET_KILL class: no handler can
 *                                 ever see it, instruction patches or
 *                                 older syscall numbers are the only
 *                                 counter ("guard cannot save");
 *   survived guarded, died bare ->  RET_TRAP class: the shim's
 *                                 guard handles it;
 *   survived both             ->  allowed (or emulated by a patch).
 *
 * usage: host-census [max_nr]        (default 463 -- the largest
 *                                     syscall number in either the
 *                                     arm64 or the x86_64 UAPI)
 *
 * The two summary lines use the same "[nproot] census:" format as the
 * shim's, so the CI verdict greps stay identical.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Immediate unbuffered stderr lines: if the parent itself dies of SIGSYS
 * mid-sweep (observed once on an AVD's genuine zygote filter), whatever
 * was classified before the death is already on the wire, and the last
 * heartbeat brackets the fatal region. */
static void census_write(const char *s, size_t n)
{
        ssize_t ignored = write(2, s, n);

        (void)ignored;
}

static void census_note(const char *prefix, long nr, const char *suffix)
{
        char buf[80];
        int n = 0, i;
        long v = nr;
        char digits[24];
        int nd = 0;

        while (prefix[n] && n < (int)sizeof(buf) - 2) {
                buf[n] = prefix[n];
                n++;
        }
        if (v < 0) {
                buf[n++] = '-';
                v = -v;
        }
        do {
                digits[nd++] = (char)('0' + (v % 10));
                v /= 10;
        } while (v);
        for (i = nd - 1; i >= 0 && n < (int)sizeof(buf) - 2; i--)
                buf[n++] = digits[i];
        while (*suffix && n < (int)sizeof(buf) - 1)
                buf[n++] = *suffix++;
        buf[n++] = '\n';
        census_write(buf, (size_t)n);
}

#ifndef SYS_rt_sigaction
#if defined(__x86_64__)
#define SYS_rt_sigaction 13
#elif defined(__aarch64__)
#define SYS_rt_sigaction 134
#endif
#endif

/* NEVER use the libc's fork(): glibc and bionic block every signal
 * (SIGSYS included) around the clone inside fork()/posix_spawn, and a
 * seccomp trap in that window makes force_sig() reset the SIGSYS
 * disposition to SIG_DFL -- the process dies with no handler run and
 * no log (observed as the census parent dying on an AVD before the
 * first heartbeat).  A raw clone(SIGCHLD) is a plain COW fork with no
 * atfork machinery and no signal-mask games. */
#ifndef NPROOT_SYS_CLONE
#if defined(__x86_64__)
#define NPROOT_SYS_CLONE 56
#elif defined(__aarch64__)
#define NPROOT_SYS_CLONE 220
#endif
#endif
#ifndef NPROOT_SYS_PIPE2
#if defined(__x86_64__)
#define NPROOT_SYS_PIPE2 293
#elif defined(__aarch64__)
#define NPROOT_SYS_PIPE2 59
#endif
#endif

/* 0 in the child, pid in the parent, -1 on error. */
static long nproot_raw_fork(void)
{
        return syscall(NPROOT_SYS_CLONE, (unsigned long)SIGCHLD,
                       0UL, 0UL, 0UL, 0UL, 0UL);
}

#define KSA_SIGINFO  4ul
#define KSA_RESTORER 0x04000000ul

/* The kernel ABI directly -- see the shim for why no libc sigaction()
 * struct can be trusted across musl/glibc/bionic. */
/* The restorer MUST be naked: after the handler returns, the kernel
 * expects RSP/SP to point at the signal frame it laid down, so the
 * stub must not have a frame of its own -- a compiled function's
 * prologue would shift SP and rt_sigreturn would restore from garbage
 * (observed as a SIGSEGV right after the first handled TRAP).
 * Top-level inline asm gives exactly the two instructions. */
#if defined(__x86_64__)
__asm__(
        ".text\n"
        ".globl nproot_sigreturn_stub\n"
        "nproot_sigreturn_stub:\n"
        "\tmov $15, %eax\n"              /* rt_sigreturn */
        "\tsyscall\n"
);
#elif defined(__aarch64__)
__asm__(
        ".text\n"
        ".globl nproot_sigreturn_stub\n"
        "nproot_sigreturn_stub:\n"
        "\tmov x8, #139\n"               /* rt_sigreturn */
        "\tsvc #0\n"
);
#endif

extern void nproot_sigreturn_stub(void);

static int ksigaction(int nr, void *handler, unsigned long flags)
{
        struct {
                void *handler;
                unsigned long flags;
                void (*restorer)(void);
                unsigned long mask;
        } sa;
        long r;

        memset(&sa, 0, sizeof(sa));
        sa.handler = handler;
        sa.flags = flags | KSA_RESTORER;
#if defined(__x86_64__) || defined(__aarch64__)
        sa.restorer = nproot_sigreturn_stub;
#endif
        r = syscall(SYS_rt_sigaction, nr, &sa, NULL,
                    sizeof(unsigned long));
        return r < 0 ? (int)r : 0;
}

static void seccomp_sigsys_emulate(int signum, siginfo_t *si, void *uctx)
{
        /* A parent-context TRAP would otherwise be invisible: log the
         * syscall number before emulating.  write() is async-signal-safe;
         * snprintf is not, hence the hand-rolled formatter.  The log is
         * capped: if the filter TRAPs something the spin loop hits (e.g.
         * nanosleep) every iteration would otherwise flood the capture. */
        static volatile int logged;

        (void)signum;
        (void)uctx;
        if (logged < 16) {
                logged++;
                census_note("[nproot] census: parent SIGSYS nr=",
#ifdef si_syscall
                            si ? (long)si->si_syscall : -1L,
#else
                            -1L,
#endif
                            "");
        }
        /* The probe only asks "did I survive?"; the value left in the
         * return register does not matter for the classification, but
         * emulate the shim anyway so an ERRNO-class filter behaves
         * identically in both tools. */
#if defined(__aarch64__)
        ((ucontext_t *)uctx)->uc_mcontext.regs[0] = (unsigned long)-38;
#elif defined(__x86_64__)
        ((ucontext_t *)uctx)->uc_mcontext.gregs[13] = (greg_t)-38;
#endif
}

/* Fork a probe child that issues syscall @nr with zeroed arguments.
 * Returns 0 survived, 1 died of SIGSYS, 2 died of something else,
 * 3 timed out, -1 fork/wait error. */
static int census_probe_one(long nr, int guarded)
{
        long pid = nproot_raw_fork();
        int status = 0, spins;

        if (pid < 0)
                return -1;
        if (pid == 0) {
                alarm(2);
                if (!guarded)
                        ksigaction(SIGSYS, NULL, 0);
                syscall(nr, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL);
                _exit(0);
        }
        for (spins = 0; ; spins++) {
                pid_t r = waitpid((pid_t)pid, &status, WNOHANG);

                if (r == (pid_t)pid)
                        break;
                if (r < 0)
                        return -1;
                /* most probes finish in microseconds: fast spin
                 * first, then 20 ms up to ~0.5 s */
                if (spins < 40)
                        usleep(200);
                else if (spins > 65) {
                        kill((pid_t)pid, SIGKILL);
                        waitpid((pid_t)pid, &status, 0);
                        return 3;
                } else
                        usleep(20000);
        }
        if (WIFSIGNALED(status))
                return WTERMSIG(status) == SIGSYS ? 1 : 2;
        return 0;
}

int main(int argc, char **argv)
{
        static const int nr_max_default = 463;
        int blocked[512], deadly[512];
        int nb = 0, nd = 0, nr, nr_max, start = 0, restarts = 0;
        char line[2600], *p;
        struct utsname un;
        ssize_t ignored;

        (void)ignored;
        nr_max = (argc > 1) ? atoi(argv[1]) : nr_max_default;
        if (nr_max < 0 || nr_max > 2000)
                nr_max = nr_max_default;

        if (ksigaction(SIGSYS, seccomp_sigsys_emulate, KSA_SIGINFO) != 0) {
                write(2, "[nproot] census: rt_sigaction failed\n", 36);
                return 1;
        }

        if (uname(&un) == 0)
                printf("[nproot] census: kernel %s %s %s\n",
                       un.sysname, un.release, un.machine);
        fflush(stdout);

        /* The sweep runs inside a disposable child that streams every
         * classification to the parent through a pipe: <int32 nr>
         * <int32 class> (1 = KILL, 2 = TRAP), nr -1 = clean end.  If
         * the sweep child is killed by a SIGSYS the parent cannot
         * intercept either, it restarts after the last classified
         * number, so a hostile filter cannot silence the census. */
        while (start <= nr_max) {
                int pfd[2], rec[2], status = 0, clean = 0, last = start - 1;
                long pid;
                unsigned char acc[sizeof(rec)];
                size_t have = 0;

                /* pipe2, never pipe: on Android 15 x86_64 the legacy
                 * pipe(2) is TRAP-class (the musl census died on it)
                 * while bionic's pipe2 is allowlisted */
                if (syscall(NPROOT_SYS_PIPE2, pfd, 0UL) != 0) {
                        write(2, "[nproot] census: pipe2 failed\n", 27);
                        return 1;
                }
                pid = nproot_raw_fork();
                if (pid < 0) {
                        write(2, "[nproot] census: clone failed\n", 26);
                        return 1;
                }
                if (pid == 0) {
                        close(pfd[0]);
                        for (nr = start; nr <= nr_max; nr++) {
                                int r = census_probe_one(nr, 1);
                                int cls = 0;

                                if (r == 1)
                                        cls = 1;
                                else if (r == 0 &&
                                         census_probe_one(nr, 0) == 1)
                                        cls = 2;
                                if (cls == 0)
                                        continue;
                                census_note(cls == 1 ?
                                            "[nproot] census: KILL nr=" :
                                            "[nproot] census: TRAP nr=",
                                            nr, "");
                                rec[0] = nr;
                                rec[1] = cls;
                                if (write(pfd[1], rec, sizeof(rec)) !=
                                    sizeof(rec))
                                        _exit(2);
                        }
                        {
                                int end[2] = { -1, 0 };

                                write(pfd[1], end, sizeof(end));
                        }
                        _exit(0);
                }
                close(pfd[1]);
                for (;;) {
                        ssize_t n = read(pfd[0], acc + have,
                                         sizeof(acc) - have);

                        if (n <= 0)
                                break;
                        have += (size_t)n;
                        if (have < sizeof(acc))
                                continue;
                        have = 0;
                        memcpy(rec, acc, sizeof(rec));
                        if (rec[0] < 0) {
                                clean = 1;
                                break;
                        }
                        last = rec[0];
                        if (rec[1] == 1) {
                                if (nd < (int)(sizeof(deadly) /
                                               sizeof(deadly[0])))
                                        deadly[nd++] = rec[0];
                                if (nb < (int)(sizeof(blocked) /
                                               sizeof(blocked[0])))
                                        blocked[nb++] = rec[0];
                        } else if (rec[1] == 2 &&
                                   nb < (int)(sizeof(blocked) /
                                              sizeof(blocked[0]))) {
                                blocked[nb++] = rec[0];
                        }
                }
                close(pfd[0]);
                waitpid((pid_t)pid, &status, 0);
                if (clean)
                        break;
                if (++restarts > 8) {
                        census_note("[nproot] census: sweep child keeps "
                                    "dying near nr ", last,
                                    " -- partial list");
                        break;
                }
                census_note("[nproot] census: sweep child died near nr ",
                            last, " -- restarting");
                start = last + 1;
        }

        p = line + snprintf(line, sizeof(line) - 8,
                            "[nproot] census: filter blocks %d:", nb);
        for (nr = 0; nr < nb && p < line + sizeof(line) - 12; nr++)
                p += snprintf(p, 12, " %d", blocked[nr]);
        *p++ = '\n';
        ignored = write(2, line, (size_t)(p - line));
        p = line + snprintf(line, sizeof(line) - 8,
                            "[nproot] census: guard cannot save %d:", nd);
        for (nr = 0; nr < nd && p < line + sizeof(line) - 12; nr++)
                p += snprintf(p, 12, " %d", deadly[nr]);
        *p++ = '\n';
        ignored = write(2, line, (size_t)(p - line));
        return 0;
}
