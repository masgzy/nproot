/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * nproot_preload.c - LD_PRELOAD path-translation shim (no ptrace).
 *
 * Route-D prototype of nproot (see docs/BACKENDS.md): instead of
 * supervising the guest from outside with ptrace(2), the path
 * translation happens inside the guest process, triggered from
 * interposed libc entry points.  Zero context switches per syscall.
 *
 * How it works
 * ------------
 *
 *   - the launcher (nproot-lite) execs the guest through its own
 *     dynamic loader, with LD_PRELOAD pointed at this shim and
 *     NPROOT_ROOT pointing at the guest rootfs directory on the host;
 *   - every interposed entry point translates the guest absolute path
 *     "/foo" into "<rootfs>/foo" before calling the real function;
 *   - high-level entry points (opendir/fopen/scandir) are hooked too:
 *     their internal openat(2) calls do not go through the PLT, but
 *     they operate on the already-translated path we hand them, so
 *     directory listing and stdio work as well;
 *   - follow-style hooks additionally resolve guest-side symlink
 *     chains (applet/loader symlinks carry guest-absolute targets the
 *     host kernel cannot follow);
 *   - execve/execv/execvp resolve shebangs and PT_INTERP themselves
 *     and exec the guest loader so chained execs stay translated
 *     (with --argv0 on glibc, and busybox applet insertion on musl);
 *     ELFs whose interpreter belongs to ANOTHER libc family (bionic
 *     on Android, a host tool bound into the guest) are exec'd
 *     natively instead, like the ptrace backend does -- rerouting
 *     them used to end in guest-loader relocation errors;
 *   - Android's app seccomp allowlist delivers SIGSYS for syscalls
 *     it does not know (rseq, clone3, faccessat2, ...); the shim
 *     catches the trap and returns ENOSYS, which is what the
 *     allowlist means, so glibc guests boot instead of dying with
 *     "Unknown signal 31" at startup (the ptrace backend gets the
 *     same effect by absorbing the stop in the tracer).
 *
 * Design notes learned the hard way:
 *
 *   - RESOLUTION MUST BE LAZY.  glibc runs constructors in reverse
 *     link-map order, so other objects' constructors (libselinux!)
 *     may call our hooks BEFORE our constructor ran.  Every hook
 *     therefore calls init_real_all_once() first.
 *   - statx(2) is deliberately NOT interposed: an unversioned statx
 *     definition in a preloaded object crashed BIND_NOW binaries
 *     (ls/stat on Ubuntu 22.04) at relocation on this kernel.
 *     Guest statx() stays untranslated; coreutils falls back to
 *     fstatat(2), which IS translated.
 *   - the shim must be built against the same libc family as the
 *     guest (glibc shim for Debian/Ubuntu, musl shim for Alpine):
 *     `make libnproot-musl.so`.
 *
 * Environment: NPROOT_ROOT (required), NPROOT_LOADER (enables the
 * execve reroute), NPROOT_DEBUG (log translations to stderr),
 * NPROOT_BINDS (optional "host:guest;host:guest" binding table),
 * NPROOT_FAKEID0 (optional, emulate proot's -0 root identity).
 *
 * Host namespaces /proc, /dev and /sys are shared into the guest
 * (what proot's typical "-b /proc -b /dev -b /sys" achieves), so
 * tools like ps(1) and uname(1)-adjacent users of /proc work out of
 * the box; NPROOT_BINDS covers everything beyond that.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <spawn.h>
#include <ucontext.h>
#include <unistd.h>

static ssize_t (*real_readlink)(const char *, char *, size_t);

/* ------------------------------------------------------------------ */
/* state                                                               */
/* ------------------------------------------------------------------ */

static const char *g_root;      /* NPROOT_ROOT, no trailing slash */
static size_t g_root_len;
static const char *g_loader;    /* NPROOT_LOADER or NULL */
static int g_debug;
static int g_guest_is_musl;     /* loader family, for the exec guard */
/* Set while the quiet census sweep runs: the ~700 probe children must
 * not flood stderr with one "seccomp trap" line each. */
static volatile int g_census_quiet;

/* Optional explicit bindings (NPROOT_BINDS), proot -b equivalent:
 * guest path prefixes rewritten to their host counterpart instead of
 * being rooted under g_root.  Longest prefix wins.  */
#define MAX_BINDS       64
struct g_bind {
        const char *host;
        size_t      host_len;
        const char *guest;
        size_t      guest_len;
};
static struct g_bind g_binds[MAX_BINDS];
static int g_nb_binds;

/* Emulate proot's -0 (fake root identity): identity syscalls report
 * 0, stat results are rewritten, EPERM from chmod/chown and EACCES
 * from read-only access() are reported as success.  See the hooks at
 * the bottom of this file.  */
static int g_fake_id0;

static void dbg(const char *fmt, ...)
{
        char buf[PATH_MAX + 128];
        va_list ap;

        if (!g_debug)
                return;
        va_start(ap, fmt);
        memcpy(buf, "[nproot] ", 9);
        vsnprintf(buf + 9, sizeof(buf) - 9, fmt, ap);
        va_end(ap);
        write(2, buf, strlen(buf));
}

/* basename without libgen's mutating dirname() family */
static const char *base_name_of(const char *path)
{
        const char *slash = strrchr(path, '/');
        return slash != NULL ? slash + 1 : path;
}

/* Does @path designate @prefix or something below it?  Component-wise:
 * "/proc/foo" matches "/proc", "/procfoo" does not.  */
static int top_prefix(const char *path, const char *prefix)
{
        size_t len = strlen(prefix);

        return strncmp(path, prefix, len) == 0 &&
               (path[len] == '/' || path[len] == '\0');
}

/* Host namespaces shared into the guest instead of being rooted into
 * the rootfs (see the file header).  */
static int is_passthrough(const char *path)
{
        return top_prefix(path, "/proc") || top_prefix(path, "/dev") ||
               top_prefix(path, "/sys");
}

/* Longest guest-prefix binding match, -1 when none.  */
static int find_bind(const char *path)
{
        int i, best = -1;

        for (i = 0; i < g_nb_binds; i++) {
                if (strncmp(path, g_binds[i].guest, g_binds[i].guest_len) != 0)
                        continue;
                if (path[g_binds[i].guest_len] != '/' &&
                    path[g_binds[i].guest_len] != '\0')
                        continue;
                if (best < 0 || g_binds[i].guest_len > g_binds[best].guest_len)
                        best = i;
        }
        return best;
}

/* Re-root a guest-absolute path (symlink target, shebang interpreter)
 * on the host: bindings first, then shared namespaces, then the rootfs
 * prefix.  */
static void reroot_guest_abs(char *buf, size_t bufsz, const char *target)
{
        int bind;

        if (is_passthrough(target)) {
                snprintf(buf, bufsz, "%s", target);
                return;
        }
        bind = find_bind(target);
        if (bind >= 0) {
                snprintf(buf, bufsz, "%s%s", g_binds[bind].host,
                         target + g_binds[bind].guest_len);
                return;
        }
        snprintf(buf, bufsz, "%s%s", g_root, target);
}

/* Translate a guest path into a host path.  Relative paths and paths
 * that are already inside the rootfs are returned untouched.  */
static const char *xlate(char *buf, size_t bufsz, const char *path)
{
        int bind;

        if (path == NULL || path[0] != '/')
                return path;
        if (g_root_len > 0 && strncmp(path, g_root, g_root_len) == 0 &&
            (path[g_root_len] == '/' || path[g_root_len] == '\0'))
                return path;    /* already translated (avoids loops) */
        if (is_passthrough(path))
                return path;
        bind = find_bind(path);
        if (bind >= 0) {
                snprintf(buf, bufsz, "%s%s", g_binds[bind].host,
                         path + g_binds[bind].guest_len);
                dbg("%s -> %s (bind)", path, buf);
                return buf;
        }
        snprintf(buf, bufsz, "%s%s", g_root, path);
        dbg("%s -> %s", path, buf);
        return buf;
}

/* Resolve guest symlinks on the host side.  The kernel resolves
 * symlink targets against the HOST root, so an applet symlink like
 * /bin/cat -> /bin/busybox (a guest-absolute target) would ENOENT.
 * Re-resolving the chain here with the interposed readlink (which
 * translates targets) fixes exec and open through such symlinks.  */
static int resolve_guest_links(char *hostpath, size_t sz)
{
        char target[PATH_MAX];
        int depth;

        for (depth = 0; depth < 8; depth++) {
                char dir[PATH_MAX], *slash;
                ssize_t r = real_readlink(hostpath, target, sizeof(target) - 1);
                if (r < 0)
                        return (errno == EINVAL) ? 0 : -1; /* not a link */
                target[r] = '\0';
                if (target[0] == '/') {
                        reroot_guest_abs(hostpath, sz, target);
                        continue;
                }
                /* relative target: join with the dirname */
                snprintf(dir, sizeof(dir), "%s", hostpath);
                slash = strrchr(dir, '/');
                if (slash == NULL)
                        return -1;
                *slash = '\0';
                snprintf(hostpath, sz, "%s/%s", dir, target);
        }
        return 0;
}

/* xlate() plus guest-side symlink resolution: for entry points whose
 * kernel counterpart follows symlinks.  Cheap: one readlink(2) that
 * returns EINVAL for regular files.
 *
 * xlate() returns either buf or the original pointer (relative,
 * passthrough and already-host paths are returned untouched), so this
 * wrapper copies the result into buf whenever xlate() did not, to
 * guarantee resolve_guest_links() operates on initialized memory.  */
static const char *xlate_follow(char *buf, size_t bufsz, const char *path)
{
        if (path == NULL || path[0] != '/')
                return path;
        if (is_passthrough(path))
                return path;    /* host path: kernel resolution is right */
        path = xlate(buf, bufsz, path);
        if (path != buf)
                snprintf(buf, bufsz, "%s", path);
        resolve_guest_links(buf, bufsz);
        return buf;
}

/* ------------------------------------------------------------------ */
/* real function pointers + lazy resolution                            */
/* ------------------------------------------------------------------ */

static int      (*real_open)(const char *, int, ...);
static int      (*real_openat)(int, const char *, int, ...);
static int      (*real_creat)(const char *, mode_t);
static int      (*real_stat)(const char *, struct stat *);
static int      (*real_lstat)(const char *, struct stat *);
static int      (*real_fstatat)(int, const char *, struct stat *, int);
static int      (*real_access)(const char *, int);
static int      (*real_faccessat)(int, const char *, int, int);
static int      (*real_unlink)(const char *);
static int      (*real_unlinkat)(int, const char *, int);
static int      (*real_rmdir)(const char *);
static int      (*real_mkdir)(const char *, mode_t);
static int      (*real_mkdirat)(int, const char *, mode_t);
static int      (*real_chmod)(const char *, mode_t);
static int      (*real_fchmodat)(int, const char *, mode_t, int);
static int      (*real_chown)(const char *, uid_t, gid_t);
static int      (*real_lchown)(const char *, uid_t, gid_t);
static int      (*real_fchownat)(int, const char *, uid_t, gid_t, int);
static int      (*real_rename)(const char *, const char *);
static int      (*real_renameat)(int, const char *, int, const char *);
static int      (*real_symlink)(const char *, const char *);
static int      (*real_symlinkat)(const char *, int, const char *);
static int      (*real_link)(const char *, const char *);
static int      (*real_linkat)(int, const char *, int, const char *, int);
static ssize_t  (*real_readlink)(const char *, char *, size_t);
static ssize_t  (*real_readlinkat)(int, const char *, char *, size_t);
static int      (*real_truncate)(const char *, off_t);
static int      (*real_utimes)(const char *, const struct timeval *);
static int      (*real_utimensat)(int, const char *, const struct timespec *, int);
static int      (*real_mknod)(const char *, mode_t, dev_t);
static int      (*real_mknodat)(int, const char *, mode_t, dev_t);
static DIR      *(*real_opendir)(const char *);
static FILE     *(*real_fopen)(const char *, const char *);
static FILE     *(*real_freopen)(const char *, const char *, FILE *);
static int      (*real_scandir)(const char *, struct dirent ***,
                                int (*)(const struct dirent *),
                                int (*)(const struct dirent **,
                                        const struct dirent **));
static void     *(*real_dlopen)(const char *, int);
static char     *(*real_getcwd)(char *, size_t);
static int      (*real_chdir)(const char *);
#ifndef __GLIBC__
static int      (*real_statx)(int, const char *, int, unsigned int,
                              struct statx *);
#endif
static int      (*real_execve)(const char *, char *const [], char *const []);
static int      (*real_execv)(const char *, char *const []);
static int      (*real_execvp)(const char *, char *const []);

/* identity family, hooked only when NPROOT_FAKEID0 is set */
static uid_t    (*real_getuid)(void);
static uid_t    (*real_geteuid)(void);
static gid_t    (*real_getgid)(void);
static gid_t    (*real_getegid)(void);
static int      (*real_setuid)(uid_t);
static int      (*real_setgid)(gid_t);
static int      (*real_seteuid)(uid_t);
static int      (*real_setegid)(gid_t);
static int      (*real_setreuid)(uid_t, uid_t);
static int      (*real_setregid)(gid_t, gid_t);
static int      (*real_setresuid)(uid_t, uid_t, uid_t);
static int      (*real_setresgid)(gid_t, gid_t, gid_t);
static int      (*real_fchmod)(int, mode_t);
static int      (*real_fchown)(int, uid_t, gid_t);

/* 64-bit fcntl/stdio aliases exist on both libcs (musl declares the
 * plain _64 functions too); the struct stat64 variants are glibc-only. */
static int      (*real_open64)(const char *, int, ...);
static int      (*real_openat64)(int, const char *, int, ...);
static int      (*real_creat64)(const char *, mode_t);
static int      (*real_truncate64)(const char *, off_t);
static FILE     *(*real_fopen64)(const char *, const char *);
#ifdef __GLIBC__
static int      (*real_stat64)(const char *, struct stat64 *);
static int      (*real_lstat64)(const char *, struct stat64 *);
static int      (*real_fstatat64)(int, const char *, struct stat64 *, int);
static int      (*real_renameat2)(int, const char *, int, const char *, unsigned);
static int      (*real_faccessat2)(int, const char *, int, int);
#endif

/* process-creation family: glibc blocks ALL signals around the
 * internal clone(2) of fork/posix_spawn, and a seccomp trap delivered
 * in that window is force_sig()ed to SIG_DFL -- the guest dies with
 * signal 31 and the SIGSYS handler never logs anything.  Interposing
 * the entry points lets the debug log bracket the window, so a silent
 * death between "window enter" and "window exit" immediately narrows
 * the killer syscall to the fork/spawn internals. */
static pid_t    (*real_fork)(void);
static int      (*real_posix_spawn)(pid_t *, const char *,
                                const posix_spawn_file_actions_t *,
                                const posix_spawnattr_t *,
                                char *const [], char *const []);
static int      (*real_posix_spawnp)(pid_t *, const char *,
                                const posix_spawn_file_actions_t *,
                                const posix_spawnattr_t *,
                                char *const [], char *const []);
static int      (*real_sigprocmask)(int, const sigset_t *, sigset_t *);
static int      (*real_pthread_sigmask)(int, const sigset_t *,
                                        sigset_t *);
static long     (*real_syscall)(long, ...);

static void init_real_all(void)
{
        real_open = dlsym(RTLD_NEXT, "open");
        real_openat = dlsym(RTLD_NEXT, "openat");
        real_creat = dlsym(RTLD_NEXT, "creat");
        real_stat = dlsym(RTLD_NEXT, "stat");
        real_lstat = dlsym(RTLD_NEXT, "lstat");
        real_fstatat = dlsym(RTLD_NEXT, "fstatat");
        real_access = dlsym(RTLD_NEXT, "access");
        real_faccessat = dlsym(RTLD_NEXT, "faccessat");
        real_unlink = dlsym(RTLD_NEXT, "unlink");
        real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
        real_rmdir = dlsym(RTLD_NEXT, "rmdir");
        real_mkdir = dlsym(RTLD_NEXT, "mkdir");
        real_mkdirat = dlsym(RTLD_NEXT, "mkdirat");
        real_chmod = dlsym(RTLD_NEXT, "chmod");
        real_fchmodat = dlsym(RTLD_NEXT, "fchmodat");
        real_chown = dlsym(RTLD_NEXT, "chown");
        real_lchown = dlsym(RTLD_NEXT, "lchown");
        real_fchownat = dlsym(RTLD_NEXT, "fchownat");
        real_rename = dlsym(RTLD_NEXT, "rename");
        real_renameat = dlsym(RTLD_NEXT, "renameat");
        real_symlink = dlsym(RTLD_NEXT, "symlink");
        real_symlinkat = dlsym(RTLD_NEXT, "symlinkat");
        real_link = dlsym(RTLD_NEXT, "link");
        real_linkat = dlsym(RTLD_NEXT, "linkat");
        real_readlink = dlsym(RTLD_NEXT, "readlink");
        real_readlinkat = dlsym(RTLD_NEXT, "readlinkat");
        real_truncate = dlsym(RTLD_NEXT, "truncate");
        real_utimes = dlsym(RTLD_NEXT, "utimes");
        real_utimensat = dlsym(RTLD_NEXT, "utimensat");
        real_mknod = dlsym(RTLD_NEXT, "mknod");
        real_mknodat = dlsym(RTLD_NEXT, "mknodat");
        real_opendir = dlsym(RTLD_NEXT, "opendir");
        real_fopen = dlsym(RTLD_NEXT, "fopen");
        real_freopen = dlsym(RTLD_NEXT, "freopen");
        real_scandir = dlsym(RTLD_NEXT, "scandir");
        real_dlopen = dlsym(RTLD_NEXT, "dlopen");
        real_getcwd = dlsym(RTLD_NEXT, "getcwd");
        real_chdir = dlsym(RTLD_NEXT, "chdir");
#ifndef __GLIBC__
        real_statx = dlsym(RTLD_NEXT, "statx");
#endif
        real_execve = dlsym(RTLD_NEXT, "execve");
        real_execv = dlsym(RTLD_NEXT, "execv");
        real_execvp = dlsym(RTLD_NEXT, "execvp");
        real_getuid = dlsym(RTLD_NEXT, "getuid");
        real_geteuid = dlsym(RTLD_NEXT, "geteuid");
        real_getgid = dlsym(RTLD_NEXT, "getgid");
        real_getegid = dlsym(RTLD_NEXT, "getegid");
        real_setuid = dlsym(RTLD_NEXT, "setuid");
        real_setgid = dlsym(RTLD_NEXT, "setgid");
        real_seteuid = dlsym(RTLD_NEXT, "seteuid");
        real_setegid = dlsym(RTLD_NEXT, "setegid");
        real_setreuid = dlsym(RTLD_NEXT, "setreuid");
        real_setregid = dlsym(RTLD_NEXT, "setregid");
        real_setresuid = dlsym(RTLD_NEXT, "setresuid");
        real_setresgid = dlsym(RTLD_NEXT, "setresgid");
        real_fchmod = dlsym(RTLD_NEXT, "fchmod");
        real_fchown = dlsym(RTLD_NEXT, "fchown");
        real_open64 = dlsym(RTLD_NEXT, "open64");
        real_openat64 = dlsym(RTLD_NEXT, "openat64");
        real_creat64 = dlsym(RTLD_NEXT, "creat64");
        real_truncate64 = dlsym(RTLD_NEXT, "truncate64");
        real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
#ifdef __GLIBC__
        real_stat64 = dlsym(RTLD_NEXT, "stat64");
        real_lstat64 = dlsym(RTLD_NEXT, "lstat64");
        real_fstatat64 = dlsym(RTLD_NEXT, "fstatat64");
        real_renameat2 = dlsym(RTLD_NEXT, "renameat2");
        real_faccessat2 = dlsym(RTLD_NEXT, "faccessat2");
#endif
        real_fork = dlsym(RTLD_NEXT, "fork");
        real_posix_spawn = dlsym(RTLD_NEXT, "posix_spawn");
        real_posix_spawnp = dlsym(RTLD_NEXT, "posix_spawnp");
        real_sigprocmask = dlsym(RTLD_NEXT, "sigprocmask");
        real_pthread_sigmask = dlsym(RTLD_NEXT, "pthread_sigmask");
        real_syscall = dlsym(RTLD_NEXT, "syscall");
}

/* ------------------------------------------------------------------ */
/* Android seccomp guard: SIGSYS -> -ENOSYS                            */
/* ------------------------------------------------------------------ */

/* The app seccomp filter Android installs in every Termux process
 * (zygote, see bionic libc/seccomp/seccomp_policy.cpp) answers
 * syscalls missing from its allowlist with SECCOMP_RET_TRAP, and the
 * kernel turns that into SIGSYS, whose default action kills the
 * process -- Termux shows this as "Unknown signal 31".  Modern glibc
 * probes such syscalls on its own:
 *
 *   rseq(2)         libc init of every glibc >= 2.35 binary (Debian
 *                   12+, Ubuntu 22.04+): dies before main();
 *   set_robust_list(2)  reported on Android 15 policies;
 *   clone3(2)       pthread_create/posix_spawn, glibc >= 2.34;
 *   faccessat2(2)   glibc >= 2.33; close_range(2), openat2(2), ...
 *
 * musl (Alpine) never issues any of them, which is exactly why musl
 * guests kept working under this shim while glibc guests died on
 * launch.  nproot's launcher additionally exports
 * GLIBC_TUNABLES=glibc.pthread.rseq=0 so the rseq probe is skipped
 * altogether; this handler is the second line of defense and covers
 * everything else.
 *
 * LIMITATION of the handler: the kernel delivers a seccomp trap with
 * force_sig(), which RESETS the disposition to SIG_DFL when the
 * signal is currently blocked -- and glibc blocks all signals around
 * pthread_create/posix_spawn.  clone3(2) from inside pthread_create
 * therefore kills the process no matter what handlers are installed
 * (verified experimentally: a raw clone3 is emulated fine, the very
 * same syscall from pthread_create is not).  The third line of
 * defense below patches the guest libc's clone3 to return -ENOSYS
 * right away, which glibc's internal callers treat exactly like an
 * old kernel: pthread_create/posix_spawn fall back to clone(2).
 *
 * A seccomp trap does NOT run the syscall: the kernel rolls the
 * registers back and delivers SIGSYS with the frame pointing after
 * the skipped instruction.  The handler can therefore emulate any
 * return value; -ENOSYS is the one every glibc probe site treats as
 * "kernel too old, take the fallback path" (clone3 -> clone,
 * faccessat2 -> faccessat, close_range -> loop, rseq -> none), which
 * is strictly better than dying.  Where no filter traps anything the
 * handler never fires, so desktop Linux runs are unaffected.  */
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

/* --- libc-independent SIGSYS guard installation ---------------------
 * The same shim .so can be preloaded into musl (its own build), glibc
 * (the guest) and bionic (a standalone census on a Termux host)
 * processes, and their `struct sigaction` layouts disagree: bionic's
 * sigset_t is one machine word while musl's and glibc's span 128
 * bytes, so a struct compiled against one libc is misread by another
 * libc's sigaction() -- bionic would silently install a plain handler
 * where SA_SIGINFO was requested.  Go straight to the kernel ABI
 * instead: the rt_sigaction syscall with the kernel's own struct and
 * sigsetsize = 8.  The restorer is ours too, so no libc trampoline is
 * assumed; SA_RESTORER (0x04000000) is required by x86_64 and honored
 * by arm64. */
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

#ifndef SYS_rt_sigaction
#if defined(__x86_64__)
#define SYS_rt_sigaction 13
#elif defined(__aarch64__)
#define SYS_rt_sigaction 134
#endif
#endif

#define KSA_SIGINFO  4ul
#define KSA_RESTORER 0x04000000ul
/* SA_NODEFER: while the emulate handler runs, SIGSYS must stay
 * DELIVERABLE.  Without it the kernel blocks SIGSYS for the handler's
 * duration, and a blocked syscall issued from within the handler (a
 * nested trap) is force_sig()ed with SIGSYS blocked -- the handler is
 * reset to SIG_DFL and the process dies on the spot with no log.  The
 * handler only touches the ucontext and does one raw write, so
 * re-entry is safe. */
#define KSA_NODEFER  0x40000000ul

#ifndef NPROOT_BUILD_ID
#define NPROOT_BUILD_ID ""
#endif

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

static void nproot_unblock_sigsys(void);

/* Fatal-signal reporter: a death by SIGILL(4)/SIGFPE(8)/SIGBUS(7)/
 * SIGSEGV(11) used to leave NOTHING on the terminal -- the launcher
 * only saw "signal 7, exit 135" (the musl container crash on the
 * device).  Print one line with the faulting ip + address, then
 * restore the default disposition and re-raise so the exit status
 * and core dump stay exactly what the kernel would have produced.
 * A guest that installs its own handler later simply overwrites
 * ours, and fork/exec children inherit it harmlessly. */
static void fatal_sig_report(int sig, siginfo_t *si, void *uctx)
{
        char b[128];
        uintptr_t pc = 0;
        int n;
        struct sigaction dfl;

#if defined(__aarch64__)
        pc = (uintptr_t)((ucontext_t *)uctx)->uc_mcontext.pc;
#elif defined(__x86_64__)
        pc = (uintptr_t)((ucontext_t *)uctx)->uc_mcontext.gregs[REG_RIP];
#endif
        n = snprintf(b, sizeof(b),
                     "[nproot] fatal signal %d at ip=%p addr=%p "
                     "(si_code=%d) -- include this line in any report\n",
                     sig, (void *)pc, si->si_addr, si->si_code);
        if (n > 0) {
                ssize_t ig = write(2, b, (size_t)n);

                (void)ig;
        }
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigaction(sig, &dfl, NULL);
        raise(sig);
}

static void seccomp_sigsys_emulate(int signum, siginfo_t *si, void *uctx)
{
        ucontext_t *uc = uctx;
        /* The first trap is logged even without NPROOT_DEBUG: on a
         * device whose filter deviates from the AOSP policy the last
         * line before a death is the single most useful diagnostic,
         * and one short write costs nothing. */
        static volatile int first_trap = 1;

        (void)signum;
        if (si == NULL || si->si_code != SYS_SECCOMP || uc == NULL)
                return;         /* not a seccomp trap: stay out of it */

        if (!g_census_quiet && (g_debug || first_trap)) {
                /* async-signal-safe enough: no libc calls, raw write.
                 * Digits are collected low-order first into a scratch
                 * and copied back high-order first -- printing them in
                 * collection order shows 224 as "422" (observed on a
                 * device build and wildly misleading). */
                char buf[48] = "[nproot] seccomp trap nr=";
                char scratch[12];
                int nr = si->si_syscall, p = 25, s = 0;
                unsigned un = (unsigned)(nr < 0 ? -nr : nr);

                first_trap = 0;
                if (nr < 0)
                        buf[p++] = '-';
                do {
                        scratch[s++] = (char)('0' + un % 10);
                        un /= 10;
                } while (un > 0 && s < (int)sizeof(scratch));
                while (s > 0)
                        buf[p++] = scratch[--s];
                if (g_debug)
                        memcpy(buf + p, " -> ENOSYS\n", 11);
                else
                        memcpy(buf + p, "\n", 2);
                write(2, buf, p + (g_debug ? 11 : 1));
        }

#if defined(__aarch64__)
        uc->uc_mcontext.regs[0] = (unsigned long)-ENOSYS;
#elif defined(__x86_64__)
        {
#ifndef REG_RAX
#define REG_RAX 13
#endif
                uc->uc_mcontext.gregs[REG_RAX] = (greg_t)-ENOSYS;
        }
#endif
        /* Other architectures: leave the frame alone; the default
         * action applies as it would without the guard.  */
}

/* Third line of defense: make the guest libc's dangerous syscalls
 * issue ENOSYS without running them.  glibc's pthread_create and
 * posix_spawn call clone3 with every signal blocked (see the handler
 * limitation above), so no handler can save that path; a patch can.
 * With -ENOSYS all internal callers take their "kernel too old, use
 * the fallback path" branch, which is all we need.
 *
 * The clone3 treatment stays the only default member of the danger
 * list: instruction-pattern patches are one false match away from
 * corrupting a random libc function (an looser "patch all matches"
 * rule was tried for faccessat2/close_range and shot the threaded
 * guest down on brand-new glibcs), so nothing joins the list without
 * device evidence from the census below. */
#ifdef NPROOT_PATCH_SYSCALLS
#include <link.h>

struct sc_patch {
        const char *name;
        const void *pat;
        size_t pat_len;
        const void *rep;
        size_t rep_len;
        int max_hits;       /* refuse the patch above this count */
};

#if defined(__x86_64__)
/* mov eax, 435 ; syscall */
static const unsigned char pat_clone3[] =
        { 0xB8, 0xB3, 0x01, 0x00, 0x00, 0x0F, 0x05 };
/* mov eax, -ENOSYS ; ret ; nop */
static const unsigned char rep_enosys[] =
        { 0xB8, 0xDA, 0xFF, 0xFF, 0xFF, 0xC3, 0x90 };
static const struct sc_patch sc_patches[] = {
        { "clone3", pat_clone3, sizeof(pat_clone3),
          rep_enosys, sizeof(rep_enosys), 1 },
};
#elif defined(__aarch64__)
/* movz x8, #435 ; svc #0 -- the width hand-written asm stubs use
 * (clone3 lives in glibc's own .S files). */
static const unsigned int pat_clone3_x8[] =
        { 0xD2803668u, 0xD4000001u };   /* 435 */
/* movn x0, #0x25 (= ~37 = -ENOSYS) ; ret */
static const unsigned int rep_enosys[] = { 0x928004A0u, 0xD65F03C0u };
static const struct sc_patch sc_patches[] = {
        { "clone3(x8)", pat_clone3_x8, sizeof(pat_clone3_x8),
          rep_enosys, sizeof(rep_enosys), 1 },
};
#else
static const struct sc_patch sc_patches[1];
#define N_SC_PATCHES 0
#endif

#ifndef N_SC_PATCHES
#define N_SC_PATCHES (int)(sizeof(sc_patches) / sizeof(sc_patches[0]))
#endif

static int patch_one_range(uintptr_t start, uintptr_t end,
                           const struct sc_patch *sp)
{
        const unsigned char *p, *base = (const unsigned char *)start;
        const unsigned char *stop = (const unsigned char *)end;
        uintptr_t hits[16];
        int count = 0, i;
        size_t pg;

        if (stop < base || (size_t)(stop - base) < sp->pat_len)
                return 0;
        for (p = base; p + sp->pat_len <= stop; p++) {
                if (memcmp(p, sp->pat, sp->pat_len) == 0 &&
                    count < (int)(sizeof(hits) / sizeof(hits[0])))
                        hits[count++] = (uintptr_t)p;
        }
        if (count == 0) {
                dbg("%s patch: pattern not found", sp->name);
                return 0;
        }
        if (count > sp->max_hits) {
                dbg("%s patch: pattern matched %d times, leaving the"
                    " libc alone", sp->name, count);
                return 0;
        }

        pg = (size_t)sysconf(_SC_PAGESIZE);
        for (i = 0; i < count; i++) {
                uintptr_t page = hits[i] & ~((uintptr_t)pg - 1);
                uintptr_t endp = (hits[i] + sp->rep_len + pg - 1) &
                                 ~((uintptr_t)pg - 1);

                if (mprotect((void *)page, endp - page,
                             PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                        dbg("%s patch: mprotect failed: %d", sp->name,
                            errno);
                        return 0;
                }
                memcpy((void *)hits[i], sp->rep, sp->rep_len);
                mprotect((void *)page, endp - page, PROT_READ | PROT_EXEC);
        }
        dbg("%s patched to ENOSYS at %p (x%d)", sp->name,
            (void *)hits[0], count);
        return 0;
}

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
        int i, j, done = 0;

        (void)size;
        (void)data;
        /* the executable itself ("") and the loader are not the guest
         * libc; match by name so a chrooted libc.so is found too */
        if (info->dlpi_name == NULL || info->dlpi_name[0] == '\0')
                return 0;
        if (strstr(info->dlpi_name, "libc.so") == NULL)
                return 0;
        for (i = 0; i < info->dlpi_phnum && !done; i++) {
                const ElfW(Phdr) *ph = &info->dlpi_phdr[i];

                if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X))
                        continue;
                for (j = 0; j < N_SC_PATCHES; j++)
                        patch_one_range(info->dlpi_addr + ph->p_vaddr,
                                        info->dlpi_addr + ph->p_vaddr +
                                        ph->p_memsz, &sc_patches[j]);
                done = 1;
        }
        return 0;
}

static void patch_dangerous_syscalls(void)
{
        dl_iterate_phdr(phdr_callback, NULL);
}
#endif

/* ------------------------------------------------------------------ */
/* Device seccomp census: which syscalls does THIS kernel's app        */
/* filter actually block, and can our guard save them?                 */
/* ------------------------------------------------------------------ */

/* NEVER use the libc's fork() for census or shield work: glibc and
 * bionic block every signal -- SIGSYS included -- around the clone
 * inside fork()/posix_spawn, and a seccomp trap issued in that window
 * makes the kernel reset the SIGSYS disposition to SIG_DFL via
 * force_sig() (the guard limitation documented above), killing the
 * process with no handler run and no log.  A raw clone(SIGCHLD) is a
 * plain COW fork with no atfork machinery and no signal-mask games,
 * and it is the one process-creation syscall the zygote policy is
 * guaranteed to allow (Termux itself could not spawn shells without
 * it). */
#ifndef NPROOT_SYS_CLONE
#if defined(__x86_64__)
#define NPROOT_SYS_CLONE 56
#elif defined(__aarch64__)
#define NPROOT_SYS_CLONE 220
#endif
#endif
#ifndef NPROOT_SYS_OPENAT
#if defined(__x86_64__)
#define NPROOT_SYS_OPENAT 257
#elif defined(__aarch64__)
#define NPROOT_SYS_OPENAT 56
#endif
#endif
#ifndef NPROOT_SYS_GETPID
#if defined(__x86_64__)
#define NPROOT_SYS_GETPID 39
#elif defined(__aarch64__)
#define NPROOT_SYS_GETPID 172
#endif
#endif
#ifndef NPROOT_SYS_UNLINK
#if defined(__x86_64__)
#define NPROOT_SYS_UNLINK 87
#elif defined(__aarch64__)
#define NPROOT_SYS_UNLINK 35
#endif
#endif
#ifndef NPROOT_SYS_READ
#if defined(__x86_64__)
#define NPROOT_SYS_READ 0
#elif defined(__aarch64__)
#define NPROOT_SYS_READ 63
#endif
#endif
#ifndef NPROOT_SYS_CLOSE
#if defined(__x86_64__)
#define NPROOT_SYS_CLOSE 3
#elif defined(__aarch64__)
#define NPROOT_SYS_CLOSE 57
#endif
#endif
#ifndef NPROOT_SYS_RENAMEAT
#if defined(__x86_64__)
#define NPROOT_SYS_RENAMEAT 264
#elif defined(__aarch64__)
#define NPROOT_SYS_RENAMEAT 38
#endif
#endif
#ifndef NPROOT_SYS_UNLINKAT
#if defined(__x86_64__)
#define NPROOT_SYS_UNLINKAT 263
#elif defined(__aarch64__)
#define NPROOT_SYS_UNLINKAT 35
#endif
#endif
#ifndef NPROOT_SYS_PIPE2
#if defined(__x86_64__)
#define NPROOT_SYS_PIPE2 293
#elif defined(__aarch64__)
#define NPROOT_SYS_PIPE2 59
#endif
#endif
#ifndef NPROOT_SYS_PROCESS_VM_READV
#if defined(__x86_64__)
#define NPROOT_SYS_PROCESS_VM_READV 310
#elif defined(__aarch64__)
#define NPROOT_SYS_PROCESS_VM_READV 270
#endif
#endif

/* The census runs inside processes whose filter traps exotic syscalls
 * (observed on Android 15 x86_64: the legacy pipe(2), nr 22, is
 * TRAP-class while bionic's pipe2(2), nr 293, is allowlisted -- musl
 * and python die on it).  Every syscall the census itself needs must
 * therefore be one bionic itself uses. */
static int nproot_pipe2(int *fds)
{
        return (int)syscall(NPROOT_SYS_PIPE2, fds, 0UL);
}

/* 0 in the child, pid in the parent, -1 on error. */
static long nproot_raw_fork(void)
{
        return syscall(NPROOT_SYS_CLONE, (unsigned long)SIGCHLD,
                       0UL, 0UL, 0UL, 0UL, 0UL);
}

/* Fork a probe child that issues syscall @nr with zeroed arguments.
 * The child is strictly disposable: zeroed arguments make every
 * known syscall fail with EFAULT/EINVAL/EPERM, privileged ones are
 * denied to the app uid anyway, and a hang (pause/select/...) is cut
 * short by the alarm and the bounded wait below.  Returns:
 * 0 survived, 1 died of SIGSYS, 2 died of something else,
 * 3 timed out, -1 fork/wait error.  With @guarded the inherited
 * SIGSYS handler stays armed (a TRAP-emulating filter is survived);
 * with !guarded the disposition is reset to SIG_DFL first (a raw
 * TRAP filter kills the probe). */
static int census_probe_one(long nr, int guarded)
{
        long pid = nproot_raw_fork();
        int status = 0, spins;

        if (pid < 0)
                return -1;
        if (pid == 0) {
                alarm(2);
                if (!guarded)
                        /* SIG_DFL via the kernel ABI: a struct built
                         * against musl would be misread by bionic. */
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
                /* most probes finish within microseconds: a fast
                 * short spin first, then the 20 ms pace up to ~0.5 s */
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

/* The whole sweep (700+ probes) runs inside a disposable sweep child
 * that streams each classification to the parent through a pipe:
 * <int32 nr> <int32 class>, class 1 = deadly (survived nothing, not
 * even the guard), 2 = TRAP-blocked (survived guarded, died bare),
 * nr -1 = clean end.  If the sweep child is itself killed by a
 * SIGSYS the guard cannot see, the parent restarts it after the last
 * classified number -- the census therefore always finishes, and the
 * restart messages pinpoint any parent-context death for free. */
static void census_sweep_child(int out, int start, int nr_max)
{
        int nr;

        for (nr = start; nr <= nr_max; nr++) {
                int r = census_probe_one(nr, 1);
                int rec[2], cls = 0;

                if (r == 1)
                        cls = 1;
                else if (r == 0 && census_probe_one(nr, 0) == 1)
                        cls = 2;
                if (cls == 0)
                        continue;
                if (g_debug) {
                        char b[64];
                        int n = snprintf(b, sizeof(b),
                                         cls == 1 ?
                                         "[nproot] census: KILL nr=%d\n" :
                                         "[nproot] census: TRAP nr=%d\n",
                                         nr);
                        ssize_t ignored = write(2, b, (size_t)n);

                        (void)ignored;
                }
                rec[0] = nr;
                rec[1] = cls;
                if (write(out, rec, sizeof(rec)) != sizeof(rec))
                        _exit(2);
        }
        {
                int rec[2] = { -1, 0 };

                if (write(out, rec, sizeof(rec)) != sizeof(rec))
                        _exit(2);
        }
        _exit(0);
}

/* 0 = clean full sweep, 1 = partial (sweep child kept dying), -1 on
 * pipe/clone failure.  blocked[] receives every blocked number
 * (deadly ones included -- the shield pre-empts both classes). */
static int census_sweep(int *blocked, int blocked_max, int *p_nb,
                        int *deadly, int deadly_max, int *p_nd,
                        int nr_max)
{
        int start = 0, restarts = 0, nb = 0, nd = 0, rc = 0;

        *p_nb = 0;
        *p_nd = 0;
        while (start <= nr_max) {
                int pfd[2], rec[2], status = 0, clean = 0, last = start - 1;
                long pid;

                if (nproot_pipe2(pfd) != 0)
                        return -1;
                pid = nproot_raw_fork();
                if (pid < 0) {
                        close(pfd[0]);
                        close(pfd[1]);
                        return -1;
                }
                if (pid == 0) {
                        close(pfd[0]);
                        census_sweep_child(pfd[1], start, nr_max);
                }
                close(pfd[1]);
                {
                        unsigned char acc[sizeof(rec)];
                        size_t have = 0;

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
                                        if (nd < deadly_max)
                                                deadly[nd++] = rec[0];
                                        if (nb < blocked_max)
                                                blocked[nb++] = rec[0];
                                } else if (rec[1] == 2 &&
                                           nb < blocked_max) {
                                        blocked[nb++] = rec[0];
                                }
                        }
                }
                close(pfd[0]);
                waitpid((pid_t)pid, &status, 0);
                if (clean)
                        break;
                if (++restarts > 8) {
                        dbg("census: sweep child keeps dying near nr %d, "
                            "continuing with a partial list", last);
                        rc = 1;
                        break;
                }
                dbg("census: sweep child died near nr %d (status %d), "
                    "restarting from %d", last, status, last + 1);
                start = last + 1;
                rc = 1;
        }
        *p_nb = nb;
        *p_nd = nd;
        return rc;
}

/* ------------------------------------------------------------------ */
/* The seccomp shield: census-driven syscall-stub hardening.           */
/*                                                                     */
/* The guard has one blind spot the kernel itself enforces:            */
/* force_sig() RESETS the SIGSYS disposition to SIG_DFL whenever the   */
/* signal is blocked or ignored at trap time, and glibc blocks every  */
/* signal around pthread_create/posix_spawn/fork.  Any TRAP-class     */
/* blocked syscall issued inside such a window therefore kills the    */
/* guest with no handler run and no log -- the silent "signal 31,     */
/* exit 159" death.  KILL-class actions bypass the handler at all     */
/* times.  The census cannot see either case: its probes run with a   */
/* clean signal mask.                                                 */
/*                                                                     */
/* Installing our own ERRNO filter does NOT help: the kernel evaluates */
/* every filter on the stack and the LOWEST action value wins         */
/* (verified on 5.10: an older TRAP, 0x00030000, always beats a newer */
/* ERRNO, 0x00050026).  There is no action below TRAP to pre-empt     */
/* with, so the only in-process counter left is the one the ptrace    */
/* backend uses too: never let the guest ISSUE a blocked syscall.     */
/*                                                                     */
/* The shield therefore scans the executable segments of every loaded */
/* object (guest libc, loader, ...) for the syscall stubs --          */
/* aarch64: "movz x8, #NR ; svc #0", x86_64: "mov eax, NR ; syscall"  */
/* -- of exactly the numbers the census found blocked, and patches    */
/* them in place to return -ENOSYS.  That is byte-for-byte the value  */
/* the guard would have emulated, so guest semantics are unchanged    */
/* where the guard worked, and strictly better where it could not run */
/* (blocked-mask windows, KILL-class actions).  Only stub patterns of */
/* blocked numbers are touched; a "movz x8, #NR; svc #0" pair IS a    */
/* syscall of NR, so a match can never be a false one.                */
/*                                                                     */
/* The census result is cached per kernel release in PROOT_TMP_DIR:   */
/* the sweep forks ~700 disposable probes (a few seconds), so only    */
/* the first guest launch pays for it.  NPROOT_SHIELD=0 disables the  */
/* shield; NPROOT_SHIELD=1 forces it on non-Android kernels (tests).  */
/* ------------------------------------------------------------------ */
#define NPROOT_SHIELD_MAX_NR 512
static unsigned char g_shield_blocked[(NPROOT_SHIELD_MAX_NR + 7) / 8];
/* Set once a verified census list has been marked: gates the generic
 * syscall() door below (the census probes themselves go through that
 * door and must keep trapping, so the door only closes AFTER the
 * census is done). */
static volatile int g_shield_armed;

static void shield_mark(const int *nrs, int n)
{
        int i;

        for (i = 0; i < n; i++)
                if (nrs[i] >= 0 && nrs[i] < NPROOT_SHIELD_MAX_NR)
                        g_shield_blocked[nrs[i] >> 3] |=
                                (unsigned char)(1u << (nrs[i] & 7));
        if (n > 0)
                __atomic_store_n(&g_shield_armed, 1, __ATOMIC_RELEASE);
}

static int shield_is_blocked(unsigned nr)
{
        if (nr >= NPROOT_SHIELD_MAX_NR)
                return 0;
        return (g_shield_blocked[nr >> 3] >> (nr & 7)) & 1;
}

/* mprotect the covering pages RWX, memcpy the replacement, restore.
 * Returns 1 on success, 0 if the pages could not be made writable --
 * callers must count only real patches, a silently skipped one would
 * fake the whole shield as working (hardened>0 means patched). */

/* Deferred patching: scanning only COLLECTS sites; the pages are then
 * made writable once per contiguous run.  The old per-stub flow issued
 * four mprotect calls per stub (two sites x RW + restore), which on a
 * 59-stub libc meant 236 mprotect syscalls per exec -- most of the
 * visible per-command latency.  One bulk round costs a handful. */
#define NPROOT_PATCH_MAX 1024

struct shield_patch {
        void *addr;
        const void *rep;
        size_t rep_len;
};

static struct shield_patch g_shield_patches[NPROOT_PATCH_MAX];
static int g_shield_npatches;

static void shield_collect(void *addr, const void *rep, size_t rep_len)
{
        if (g_shield_npatches < NPROOT_PATCH_MAX) {
                g_shield_patches[g_shield_npatches].addr = addr;
                g_shield_patches[g_shield_npatches].rep = rep;
                g_shield_patches[g_shield_npatches].rep_len = rep_len;
                g_shield_npatches++;
        }
}

static int shield_patch_cmp(const void *a, const void *b)
{
        uintptr_t xa = (uintptr_t)((const struct shield_patch *)a)->addr;
        uintptr_t xb = (uintptr_t)((const struct shield_patch *)b)->addr;

        return xa < xb ? -1 : (xa > xb ? 1 : 0);
}

static int shield_patch_at(void *addr, size_t len,
                           const void *rep, size_t rep_len)
{
        size_t pg = (size_t)sysconf(_SC_PAGESIZE);
        uintptr_t page = (uintptr_t)addr & ~((uintptr_t)pg - 1);
        uintptr_t endp = ((uintptr_t)addr + len + pg - 1) &
                         ~((uintptr_t)pg - 1);

        if (mprotect((void *)page, endp - page,
                     PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
                return 0;
        memcpy(addr, rep, rep_len);
        mprotect((void *)page, endp - page, PROT_READ | PROT_EXEC);
        return 1;
}

/* Apply every collected site: sort by address, group the covering
 * pages into runs, mprotect each run RWX once, write, restore once.
 * A run whose mprotect fails falls back to the per-stub path so the
 * count still only reflects sites actually patched. */
static int shield_apply_patches(void)
{
        size_t pg = (size_t)sysconf(_SC_PAGESIZE);
        int base, ok = 0;

        if (g_shield_npatches == 0)
                return 0;
        qsort(g_shield_patches, (size_t)g_shield_npatches,
              sizeof(g_shield_patches[0]), shield_patch_cmp);
        base = 0;
        while (base < g_shield_npatches) {
                uintptr_t start = (uintptr_t)g_shield_patches[base].addr &
                                  ~((uintptr_t)pg - 1);
                uintptr_t end = start + pg;
                int i2;

                for (i2 = base + 1; i2 < g_shield_npatches; i2++) {
                        uintptr_t page =
                                (uintptr_t)g_shield_patches[i2].addr &
                                ~((uintptr_t)pg - 1);

                        if (page < end)
                                continue;       /* inside the run */
                        if (page == end) {
                                end += pg;
                                continue;
                        }
                        break;                  /* next run starts here */
                }
                if (mprotect((void *)start, end - start,
                             PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
                        int j;

                        for (j = base; j < i2; j++) {
                                memcpy(g_shield_patches[j].addr,
                                       g_shield_patches[j].rep,
                                       g_shield_patches[j].rep_len);
                                ok++;
                        }
                        mprotect((void *)start, end - start,
                                 PROT_READ | PROT_EXEC);
                } else {
                        int j;

                        for (j = base; j < i2; j++) {
                                if (shield_patch_at(
                                            g_shield_patches[j].addr,
                                            g_shield_patches[j].rep_len,
                                            g_shield_patches[j].rep,
                                            g_shield_patches[j].rep_len))
                                        ok++;
                        }
                }
                base = i2;
        }
        g_shield_npatches = 0;
        return ok;
}

/* ---- EFAULT-safe view of the scanned memory ------------------------
 * The scan used to read the guest mappings straight out of the live
 * address space, which is exactly what /proc/self/maps promises is
 * mapped.  On a real musl device that read died with SIGBUS
 * BUS_ADRERR (si_code=2) at a FIXED offset inside an executable
 * file-backed mapping: a mapping can cover pages the backing file no
 * longer provides (a short or mutated rootfs image), and nobody
 * touches those pages until this scanner comes along -- the loader
 * only reads headers/dynamic/relocations, and the guest has not
 * started running yet.  process_vm_readv(2) on self answers EFAULT
 * for such pages instead of faulting, so the snapshot copies the
 * range page-by-page, 0xFF-fills whatever is unreadable (no stub
 * pattern can match 0xFF), and the scan proceeds over what is really
 * there. */
static int g_shield_pvmr;       /* 0 unknown, 1 usable, -1 unusable */

static long shield_pvmr_copy(void *local, uintptr_t remote, size_t len)
{
        struct iovec liov, riov;
        static long pid = -1;

        if (pid < 0)
                pid = syscall(NPROOT_SYS_GETPID);
        liov.iov_base = local;
        liov.iov_len = len;
        riov.iov_base = (void *)remote;
        riov.iov_len = len;
        return syscall(NPROOT_SYS_PROCESS_VM_READV, pid,
                       &liov, 1UL, &riov, 1UL, 0UL);
}

/* One-time probe against the shim's own data (always mapped): a
 * failure here means the syscall itself is unavailable -- old kernel,
 * or the app filter blocks/traps it, in which case the generic
 * syscall() door refuses the number before the kernel ever sees it.
 * The caller then scans the live memory as before, which is fine on
 * every kernel where no mapping covers pages beyond the backing
 * file's EOF (i.e. everywhere this crash has not been observed). */
static int shield_pvmr_usable(void)
{
        int probe = 0;
        long r;

        if (g_shield_pvmr == 0) {
                r = shield_pvmr_copy(&probe, (uintptr_t)&probe,
                                     sizeof(probe));
                g_shield_pvmr = (r == (long)sizeof(probe)) ? 1 : -1;
        }
        return g_shield_pvmr > 0;
}

/* Copy [start, end) into a fresh anonymous buffer.  Returns 0 with
 * *@data_out = the buffer (munmap it once scanned, length = end -
 * start); unreadable pages are 0xFF-filled and counted in
 * *@skipped_out.  Returns -1 when process_vm_readv cannot be used --
 * the caller falls back to scanning the live memory. */
static int shield_snapshot_range(uintptr_t start, uintptr_t end,
                                 unsigned char **data_out, int *skipped_out)
{
        size_t pg = (size_t)sysconf(_SC_PAGESIZE);
        size_t len = (size_t)(end - start), done = 0, chunk;
        unsigned char *buf;
        long r;

        *skipped_out = 0;
        buf = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED)
                return -1;
        while (done < len) {
                r = shield_pvmr_copy(buf + done, start + done,
                                     len - done);
                if (r > 0) {
                        done += (size_t)r;
                        continue;
                }
                if (r < 0 && errno != EFAULT) {
                        munmap(buf, len);
                        return -1;
                }
                /* a page in the rest is unreadable: walk the remainder
                 * one page at a time, skipping whatever faults */
                for (;;) {
                        chunk = pg - ((start + done) & (pg - 1));
                        if (chunk > len - done)
                                chunk = len - done;
                        r = shield_pvmr_copy(buf + done, start + done,
                                             chunk);
                        if (r == (long)chunk) {
                                done += chunk;
                        } else {
                                if (r < 0 && errno != EFAULT &&
                                    errno != ENOMEM) {
                                        munmap(buf, len);
                                        return -1;
                                }
                                memset(buf + done, 0xFF, chunk);
                                done += chunk;
                                (*skipped_out)++;
                        }
                        if (done >= len)
                                break;
                }
        }
        *data_out = buf;
        return 0;
}

/* Scan [start, end) for stubs of blocked numbers; @data is the bytes
 * to scan (a snapshot buffer, or (const unsigned char *)start for the
 * legacy live-memory scan).  Patch sites are still reported as guest
 * addresses (start + offset).  Returns patches made. */
static int shield_scan_range(uintptr_t start, uintptr_t end,
                             const unsigned char *data)
{
        uintptr_t len, off;
        int patched = 0;

        if (end <= start)
                return 0;
        len = end - start;

#if defined(__aarch64__)
        /* mov x0, #-ENOSYS ; nop -- the ORIGINAL code after the svc
         * (cmp/ret error handling) keeps running: a mid-function stub
         * (setuid's raw-syscall path) must not get a "ret" injected */
        static const unsigned int rep[2] = { 0x928004A0u, 0xD503201Fu };

        for (off = 0; off + 8 <= len; off += 4) {
                unsigned int ins, nr;
                int w, svc_w = 0;

                memcpy(&ins, data + off, 4);
                /* The fixed pattern INCLUDING Rd: syscall numbers go in
                 * x8 by ABI, and glibc/bionic stubs are always "movz
                 * x8, #nr".  0xD2800008 keeps the x8 register field in
                 * the compare -- a mask that drops Rd would also need
                 * to compare against 0xD2800000 AND read Rd, which is
                 * exactly how a "hardened 0" regression looked on a
                 * real device (every x8 stub was silently rejected).
                 *
                 * glibc's C-wrapper syscalls -- faccessat2, openat2,
                 * statx, close_range, anything implemented in C via
                 * INTERNAL_SYSCALL -- emit the 32-bit form "movz w8,
                 * #nr" (0x52800008) instead; W8 zero-extends into X8
                 * before the svc, so the kernel sees the same number.
                 * On the real-device log that motivated this matcher,
                 * faccessat2 (nr 439) sat blocked-but-unpatched for
                 * exactly this reason while 58 X8-form stubs were
                 * hardened.  Accept both. */
                if ((ins & 0xFFE0001Fu) != 0xD2800008u &&
                    (ins & 0xFFE0001Fu) != 0x52800008u)
                        continue;       /* not "movz x8/w8, #imm16" */
                nr = (ins >> 5) & 0xFFFFu;
                if (!shield_is_blocked(nr))
                        continue;
                /* The svc is USUALLY the next word, but compiler
                 * scheduling may interleave clobber-free instructions
                 * between the number load and the svc.  Search a
                 * window so such stubs are still hardened; a stray
                 * "movz x8, #imm" that never feeds an svc is left
                 * alone (windows without svc are not patch targets).
                 * Another x8/w8 number load before the svc means the
                 * first svc would execute THAT load's number, so the
                 * pairing is ambiguous -- stop there rather than
                 * patch the wrong svc (the scanner picks the pair up
                 * from that load instead). */
                for (w = 1; w <= 8; w++) {
                        unsigned int word;

                        if (off + 4 + 4 * w > len)
                                break;
                        memcpy(&word, data + off + 4 * w, 4);
                        if (word == 0xD4000001u) {
                                svc_w = w;
                                break;  /* "svc #0" found */
                        }
                        if ((word & 0xFFE0001Fu) == 0xD2800008u ||
                            (word & 0xFFE0001Fu) == 0x52800008u)
                                break;
                }
                if (svc_w == 0)
                        continue;       /* no svc consuming this movz */
                shield_collect((void *)(start + off), &rep[0], 4);
                shield_collect((void *)(start + off + 4 * svc_w),
                               &rep[1], 4);
                patched++;
                dbg("shield: queued nr=%u stub at %p (svc +%d)",
                    nr, (void *)(start + off), svc_w);
                off += 4 * svc_w;       /* consumed through the svc */
        }
#elif defined(__x86_64__)
        /* mov eax, -ENOSYS ; nop ; nop -- same rule: the original
         * cmp/jae/ret error handling after the syscall keeps running */
        static const unsigned char rep[7] =
                { 0xB8, 0xDA, 0xFF, 0xFF, 0xFF, 0x90, 0x90 };

        for (off = 0; off + 7 <= len; off++) {
                const unsigned char *p = data + off;
                unsigned nr;

                if (p[0] != 0xB8 || p[5] != 0x0F || p[6] != 0x05)
                        continue;       /* not "mov eax, imm32; syscall" */
                memcpy(&nr, p + 1, 4);
                if (!shield_is_blocked(nr))
                        continue;
                /* the patch site is the GUEST address (start + off); p
                 * may point into the snapshot buffer */
                shield_collect((void *)(start + off), rep, sizeof(rep));
                patched++;
                dbg("shield: queued nr=%u stub at %p", nr,
                    (void *)(start + off));
                off += 6;
        }
#endif
        return patched;
}

/* Walk the executable file-backed mappings from /proc/self/maps --
 * libc-agnostic (bionic's <link.h> does not expose dl_phdr_info to
 * zig builds), and it also covers static guests.  The shim itself is
 * skipped: its sigreturn stub (mov eax,15; syscall) must never be
 * hardened even if the filter ever traps rt_sigreturn. */
#define NPROOT_SHIELD_MAPS_BUF 16384

/* self-description for the summary line: how many executable mappings
 * the walk actually scanned -- a real-device log with "hardened 0"
 * and a healthy scanned count points at the matcher, a scanned count
 * of 0 points at the maps parser */
static int g_shield_scan_ranges;

/* Hand-rolled parsers: glibc 2.38+ redirects strtol/strtoul to
 * __isoc23_* symbols (versioned GLIBC_2.38), which would make the
 * shim unloadable on older guest libcs. */
static unsigned long shield_parse_hex(const char **pp)
{
        unsigned long v = 0;
        const char *p = *pp;

        for (;;) {
                int c = *p, d;

                if (c >= '0' && c <= '9')
                        d = c - '0';
                else if (c >= 'a' && c <= 'f')
                        d = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F')
                        d = c - 'A' + 10;
                else
                        break;
                v = v * 16ul + (unsigned long)d;
                p++;
        }
        *pp = p;
        return v;
}

static long shield_parse_dec(const char **pp)
{
        long v = 0;
        const char *p = *pp;
        int neg = 0;

        if (*p == '-') {
                neg = 1;
                p++;
        }
        while (*p >= '0' && *p <= '9') {
                v = v * 10 + (*p - '0');
                p++;
        }
        *pp = p;
        return neg ? -v : v;
}

static int shield_harden_maps(void)
{
        char buf[NPROOT_SHIELD_MAPS_BUF + 2048];
        char line[1024];
        size_t have = 0;
        long fd;
        int patched = 0;

        fd = syscall(NPROOT_SYS_OPENAT, (unsigned long)-100 /* AT_FDCWD */,
                     "/proc/self/maps", 0UL, 0UL);
        if (fd < 0)
                return 0;
        for (;;) {
                long n = syscall(NPROOT_SYS_READ, fd,
                                 buf + have,
                                 (long)(sizeof(buf) - 1 - have));
                char *nl, *p;

                if (n <= 0)
                        break;
                have += (size_t)n;
                buf[have] = '\0';
                p = buf;
                while ((nl = strchr(p, '\n')) != NULL) {
                        unsigned long start, end;
                        char *q, *path;
                        int perms_x = 0;

                        *nl = '\0';
                        if (strlen(p) < sizeof(line)) {
                                memcpy(line, p, strlen(p) + 1);
                                const char *cp = line;

                                start = shield_parse_hex(&cp);
                                q = (char *)cp;
                                if (*q == '-') {
                                        q++;
                                        cp = q;
                                        end = shield_parse_hex(&cp);
                                        q = (char *)cp;
                                        /* "start-end perms offset dev inode
                                         * path": the path is the field after
                                         * the fifth space-adjacent token;
                                         * the executable bit is the third
                                         * character of the perms field */
                                        path = NULL;
                                        if (end > start) {
                                                int sp, fields = 0;

                                                for (sp = 0; line[sp] != '\0';
                                                     sp++) {
                                                        if (line[sp] == ' ' &&
                                                            line[sp + 1] != ' ' &&
                                                            line[sp + 1] != '\0') {
                                                                fields++;
                                                                if (fields == 1)
                                                                        perms_x = (line[sp + 3] == 'x');
                                                        }
                                                        if (fields == 5)
                                                                break;
                                                }
                                                if (fields == 5 &&
                                                    line[sp] == ' ' &&
                                                    line[sp + 1] == '/' )
                                                        path = line + sp + 1;
                                        }
                                        if (path != NULL && perms_x &&
                                            strncmp(path, "/system/lib", 11) != 0 &&
                                            strstr(path, "libnproot") == NULL) {
                                                int hits, skipped = 0;
                                                unsigned char *snap = NULL;
                                                const unsigned char *data =
                                                        (const unsigned char *)
                                                        start;

                                                g_shield_scan_ranges++;
                                                if (shield_pvmr_usable() &&
                                                    shield_snapshot_range(
                                                            start, end, &snap,
                                                            &skipped) == 0)
                                                        data = snap;
                                                hits = shield_scan_range(start,
                                                                         end,
                                                                         data);
                                                if (snap != NULL)
                                                        munmap(snap,
                                                               (size_t)(end -
                                                                        start));
                                                /* count STUBS, not mappings:
                                                 * "hardened 3" once meant "3
                                                 * mappings had hits" while 54
                                                 * stubs had actually been
                                                 * patched -- wildly misleading
                                                 * on a diagnosis log */
                                                patched += hits;
                                                if (skipped > 0)
                                                        dbg("shield: %s: "
                                                            "skipped %d unreada"
                                                            "ble page(s) in "
                                                            "[%lx,%lx)", path,
                                                            skipped,
                                                            (unsigned long)start,
                                                            (unsigned long)end);
                                        }
                                }
                        }
                        p = nl + 1;
                }
                have -= (size_t)(p - buf);
                memmove(buf, p, have);
        }
        syscall(NPROOT_SYS_CLOSE, fd);
        /* one bulk mprotect round covers everything collected above;
         * the return value is the count of sites actually written */
        if (g_shield_npatches > 0)
                patched = shield_apply_patches();
        return patched;
}

static void shield_cache_path(char *buf, size_t cap)
{
        const char *dir = getenv("PROOT_TMP_DIR");
        struct utsname un;
        char rel[128];
        size_t i;

        if (dir == NULL || dir[0] == '\0')
                dir = getenv("TMPDIR");
        if (dir == NULL || dir[0] == '\0')
                dir = "/data/data/com.termux/files/usr/tmp";
        rel[0] = '?';
        rel[1] = '\0';
        if (uname(&un) == 0) {
                snprintf(rel, sizeof(rel), "%s", un.release);
                for (i = 0; rel[i]; i++)
                        if (!((rel[i] >= '0' && rel[i] <= '9') ||
                              (rel[i] >= 'a' && rel[i] <= 'z') ||
                              (rel[i] >= 'A' && rel[i] <= 'Z') ||
                              rel[i] == '.' || rel[i] == '-' ||
                              rel[i] == '_'))
                                rel[i] = '_';
        }
        snprintf(buf, cap, "%s/nproot-seccomp-v1-%s", dir, rel);
}

/* -1 = no usable cache, otherwise the cached count (0 = verified
 * "nothing blocked").  A cache written for a different kernel is
 * worthless: the filter ships with the OS. */
static int shield_cache_load(int *nrs, int max)
{
        char path[512], buf[8192];
        struct utsname un;
        char *p, *nl;
        long fd, n, len;

        shield_cache_path(path, sizeof(path));
        /* raw syscalls: the interposed open()/getpid() would push the
         * cache path through the shim's own translation table */
        fd = syscall(NPROOT_SYS_OPENAT, (unsigned long)-100 /* AT_FDCWD */,
                     path, 0UL /* O_RDONLY */, 0UL);
        if (fd < 0)
                return -1;
        len = (int)syscall(NPROOT_SYS_READ, fd, buf, sizeof(buf) - 1);
        syscall(NPROOT_SYS_CLOSE, fd);
        if (len <= 0)
                return -1;
        buf[len] = '\0';
        if (strncmp(buf, "v1 ", 3) != 0)
                return -1;
        nl = strchr(buf, '\n');
        if (nl == NULL)
                return -1;
        *nl = '\0';
        if (uname(&un) != 0 || strcmp(buf + 3, un.release) != 0)
                return -1;
        n = 0;
        p = nl + 1;
        while (*p != '\0' && n < max) {
                long v;
                const char *before;

                /* the save format is " %d": the leading space before
                 * every number used to stop this parser dead on the
                 * first field, so the cache NEVER loaded and every
                 * process re-ran the whole ~700-probe sweep (the
                 * per-command latency on the device).  Skip separators
                 * before each number. */
                while (*p == ' ' || *p == '\n' || *p == '\t')
                        p++;
                before = p;

                v = shield_parse_dec((const char **)&p);
                if (p == before)
                        break;          /* not a number: stop parsing */
                if (v >= 0 && v <= 2000)
                        nrs[n++] = (int)v;
                while (*p == ' ' || *p == '\n')
                        p++;
        }
        return n;
}

static void shield_cache_save(const int *nrs, int n)
{
        char path[512], tmp[560], line[2600], *p;
        struct utsname un;
        long fd;
        int i;
        ssize_t ignored;

        if (uname(&un) != 0)
                return;
        shield_cache_path(path, sizeof(path));
        snprintf(tmp, sizeof(tmp), "%s.%ld", path,
                 syscall(NPROOT_SYS_GETPID));
        syscall(NPROOT_SYS_UNLINKAT, (unsigned long)-100, tmp, 0UL);
        fd = syscall(NPROOT_SYS_OPENAT, (unsigned long)-100, tmp,
                     0100 | 01 /* O_CREAT|O_WRONLY */ | 02000 /* O_TRUNC */,
                     0600ul);
        if (fd < 0)
                return;
        p = line + snprintf(line, sizeof(line) - 2, "v1 %s\n", un.release);
        for (i = 0; i < n; i++)
                p += snprintf(p, 12, " %d", nrs[i]);
        *p++ = '\n';
        ignored = write((int)fd, line, (size_t)(p - line));
        if (syscall(NPROOT_SYS_CLOSE, fd) == 0 &&
            syscall(NPROOT_SYS_RENAMEAT, (unsigned long)-100,
                    tmp, (unsigned long)-100, path) != 0)
                syscall(NPROOT_SYS_UNLINKAT, (unsigned long)-100, tmp, 0UL);
        (void)ignored;
}

static int android_host(void)
{
        struct utsname un;

        return uname(&un) == 0 && strstr(un.release, "android") != NULL;
}

static void shield_log(const char *fmt, ...)
{
        char buf[256];
        va_list ap;
        int n;

        memcpy(buf, "[nproot] ", 9);
        va_start(ap, fmt);
        n = vsnprintf(buf + 9, sizeof(buf) - 16, fmt, ap);
        va_end(ap);
        if (n > 0) {
                size_t len = (size_t)n + 9;

                if (len > sizeof(buf) - 2)
                        len = sizeof(buf) - 2;
                buf[len++] = '\n';
                write(2, buf, len);
        }
}

/* Arm the shield from a blocked-number list: mark the bitmap and
 * harden every loaded object's stubs. */
static int shield_arm(const int *nrs, int n)
{
        shield_mark(nrs, n);
        return shield_harden_maps();
}

/* Ordinary guest launch on an Android kernel: harden the stubs from
 * the cached census, running the sweep once, silently, when no cache
 * exists yet.  Non-Android kernels have no app filter -- skip the
 * fork cost entirely. */
static void shield_from_cache(void)
{
        static const int nr_max = 463;
        int blocked[512], deadly[512];
        int nb = 0, nd = 0, n, partial = 0, patched;

        if (getenv("NPROOT_SHIELD") != NULL &&
            strcmp(getenv("NPROOT_SHIELD"), "0") == 0)
                return;
        n = shield_cache_load(blocked, 512);
        if (n < 0 || (n == 0 && android_host())) {
                /* An empty census on a filtered kernel is not
                 * trustworthy: a poisoned or half-written cache, or a
                 * quiet sweep whose children kept dying (the restart
                 * chatter is debug-gated, so the failure was silent),
                 * would otherwise keep the shield disarmed forever
                 * after -- observed on the device as an early death
                 * with "census found nothing blocked".  Re-sweep; an
                 * empty result is only believed when this process
                 * proved it itself. */
                g_census_quiet = 1;
                partial = census_sweep(blocked, 512, &nb,
                                       deadly, 512, &nd, nr_max);
                g_census_quiet = 0;
                if (partial == 0)
                        shield_cache_save(blocked, nb);
                n = nb;
        }
        if (n > 0) {
                patched = shield_arm(blocked, n);
                /* the per-process summary used to be unconditional:
                 * every exec of every command printed one line to the
                 * terminal.  Quiet unless debugging now. */
                if (g_debug)
                        shield_log("seccomp shield: hardened %d blocked-syscall "
                                   "stubs (census: %d blocked, scanned %d exec "
                                   "mappings)", patched, n, g_shield_scan_ranges);
        } else if (n == 0 && partial == 0) {
                if (g_debug)
                        shield_log("seccomp shield: census found nothing blocked");
        } else if (n == 0) {
                shield_log("seccomp shield: census FAILED (partial "
                           "sweep) -- shield NOT armed; re-run with "
                           "NPROOT_DEBUG=1");
        }
}

/* Explicit census (NPROOT_CENSUS=1, launcher debug level): sweep
 * verbosely, print the two summary lines, arm the shield from the
 * fresh list and refresh the cache. */
static void seccomp_census(void)
{
        static const int nr_max = 463;
        int blocked[512], deadly[512];
        int nb = 0, nd = 0, i, partial;
        char line[2600], *p;
        struct utsname un;
        ssize_t ignored;

        if (uname(&un) == 0) {
                int n = snprintf(line, sizeof(line),
                                 "[nproot] census: kernel %s %s %s\n",
                                 un.sysname, un.release, un.machine);
                if (n > 0)
                        ignored = write(2, line, (size_t)n);
        }
        partial = census_sweep(blocked, 512, &nb, deadly, 512, &nd, nr_max);
        p = line + snprintf(line, sizeof(line) - 8,
                            "[nproot] census: filter blocks %d:%s", nb,
                            partial ? " (partial)" : "");
        for (i = 0; i < nb && p < line + sizeof(line) - 12; i++)
                p += snprintf(p, 12, " %d", blocked[i]);
        *p++ = '\n';
        ignored = write(2, line, (size_t)(p - line));
        p = line + snprintf(line, sizeof(line) - 8,
                            "[nproot] census: guard cannot save %d:", nd);
        for (i = 0; i < nd && p < line + sizeof(line) - 12; i++)
                p += snprintf(p, 12, " %d", deadly[i]);
        *p++ = '\n';
        ignored = write(2, line, (size_t)(p - line));
        if (nb > 0) {
                int patched = shield_arm(blocked, nb);

                snprintf(line, sizeof(line),
                         "[nproot] shield: hardened %d blocked-syscall "
                         "stubs (census: %d blocked, %d unsaveable, "
                         "scanned %d exec mappings)\n",
                         patched, nb, nd, g_shield_scan_ranges);
                ignored = write(2, line, strlen(line));
        }
        if (partial == 0)
                shield_cache_save(blocked, nb);
        (void)ignored;
}

/* Constructors of preloaded libraries may run AFTER other objects'
 * constructors (glibc runs them in reverse link-map order), so guest
 * code can call our hooks before the constructor had a chance: every
 * hook therefore ensures the real pointers are resolved first.  */
static void init_real_all_once(void)
{
        static int inited;

        if (__atomic_load_n(&inited, __ATOMIC_ACQUIRE))
                return;
        init_real_all();
        __atomic_store_n(&inited, 1, __ATOMIC_RELEASE);
}

__attribute__((constructor))
static void nproot_preload_init(void)
{
        static const char none[] = "";

        g_root = getenv("NPROOT_ROOT");
        g_loader = getenv("NPROOT_LOADER");
        g_debug = getenv("NPROOT_DEBUG") != NULL;

        /* Same-zip assertion: the launcher exports the version string
         * its own build embedded.  A preload left over from an older
         * install silently misses every fix the installed launcher's
         * release advertises (observed in the field as "still dying
         * after the upgrade" when only the nproot binary had been
         * replaced).  Not debug-gated: this is exactly the silent
         * misconfiguration class worth shouting about. */
        if (NPROOT_BUILD_ID[0] != '\0') {
                const char *bid = getenv("NPROOT_BUILD_ID");

                if (bid != NULL && strcmp(bid, NPROOT_BUILD_ID) != 0) {
                        static const char m1[] =
                                "[nproot] \u8b66\u544a: preload/libnproot.so \u4e0e nproot \u4e3b\u7a0b\u5e8f\u7248\u672c\u4e0d\u4e00\u81f4\uff08shim="
                                NPROOT_BUILD_ID "\uff0c\u4e3b\u7a0b\u5e8f=";
                        static const char m2[] =
                                "\uff09\u2014\u2014\u8bf7\u6574\u5957\u91cd\u65b0\u5b89\u88c5\uff1anproot \u4e0e preload/ \u5fc5\u987b\u6765\u81ea\u540c\u4e00\u4e2a zip \u5305\n";
                        size_t __attribute__((unused)) l1 = sizeof(m1) - 1;
                        ssize_t ig;

                        ig = write(2, m1, l1);
                        ig = write(2, bid, strlen(bid));
                        ig = write(2, m2, sizeof(m2) - 1);
                        (void)ig;
                }
        }

        /* A posix_spawn()/vfork child inherits the parent's
         * mid-window all-signals-blocked mask THROUGH execve (the
         * kernel keeps t->blocked), and glibc's internal exec paths
         * never cross a hook we could unblock from.  Clear SIGSYS
         * before anything else runs; the self-healing unblock also
         * re-arms the guard if a previous force_sig() reset it, which
         * turns a pending SIG_DFL kill into a harmless emulated
         * return. */
        nproot_unblock_sigsys();

        /* The SIGSYS guard, the libc patches and the census do not
         * depend on any nproot environment, so they run BEFORE the
         * NPROOT_ROOT gate below.  That makes the shim usable as a
         * standalone probe on any Android process -- Termux shell,
         * AVD runner, device shell -- without a guest:
         *
         *   LD_PRELOAD=<shim> NPROOT_CENSUS=1 /system/bin/sh -c :
         *
         * which prints the whole picture of the filter this process
         * inherited (zygote's app policy on a device or emulator),
         * including whether blocks are catchable TRAPs or uncatchable
         * KILLs -- exactly what a silent death needs to be explained.
         * Guest launches take the same path as before; only the order
         * within this constructor changed. */
        if (ksigaction(SIGSYS, seccomp_sigsys_emulate,
                       KSA_SIGINFO | KSA_NODEFER) == 0)
                dbg("seccomp SIGSYS guard installed");
        else
                dbg("rt_sigaction(SIGSYS) failed: %d", errno);

        /* Fatal-signal reporter (see fatal_sig_report above): the
         * device musl crash surfaced only as "signal 7, exit 135"
         * with zero evidence to work from. */
        {
                struct sigaction fsa;

                memset(&fsa, 0, sizeof(fsa));
                fsa.sa_sigaction = fatal_sig_report;
                fsa.sa_flags = SA_SIGINFO;
                sigemptyset(&fsa.sa_mask);
                sigaction(SIGILL, &fsa, NULL);
                sigaction(SIGFPE, &fsa, NULL);
                sigaction(SIGBUS, &fsa, NULL);
                sigaction(SIGSEGV, &fsa, NULL);
        }

#ifdef NPROOT_PATCH_SYSCALLS
        patch_dangerous_syscalls();
#endif

        /* One-shot census, requested by the launcher at debug level or
         * directly via NPROOT_CENSUS=1: probe every syscall number in
         * a disposable sweep child and report what this kernel's app
         * filter blocks and what not even the guard can save, then
         * arm the shield from the fresh list.  Unset first so forked
         * probes and guest children never repeat the sweep.
         *
         * Ordinary guest launches on an Android kernel take the quiet
         * path instead: load the cached census (sweeping once if it
         * does not exist yet) and arm the shield -- the guest then
         * never sees SIGSYS for any blocked syscall, which also
         * covers the all-signals-blocked fork/posix_spawn windows
         * where force_sig() resets the handler and no trap log can
         * ever appear. */
        if (getenv("NPROOT_CENSUS") != NULL) {
                unsetenv("NPROOT_CENSUS");
                seccomp_census();
        } else if (g_root != NULL &&
                   (android_host() || getenv("NPROOT_SHIELD") != NULL)) {
                shield_from_cache();
        }
        if (g_root == NULL) {
                /* Not launched by nproot-lite; stay inert.  */
                g_root = none;
                g_root_len = 0;
                return;
        }
        g_root_len = strlen(g_root);
        while (g_root_len > 1 && g_root[g_root_len - 1] == '/')
                g_root_len--;   /* normalize trailing slash */
        g_guest_is_musl = g_loader != NULL &&
                          strstr(g_loader, "ld-musl") != NULL;

        /* NPROOT_BINDS: "host:guest;host:guest" pairs.  */
        {
                static char spec[8192];
                const char *env = getenv("NPROOT_BINDS");
                char *save = NULL, *pair;

                if (env != NULL) {
                        snprintf(spec, sizeof(spec), "%s", env);
                        for (pair = strtok_r(spec, ";", &save);
                             pair != NULL && g_nb_binds < MAX_BINDS;
                             pair = strtok_r(NULL, ";", &save)) {
                                char *colon = strchr(pair, ':');

                                if (colon == NULL || colon == pair ||
                                    colon[1] == '\0')
                                        continue;
                                *colon = '\0';
                                g_binds[g_nb_binds].host = pair;
                                g_binds[g_nb_binds].host_len = strlen(pair);
                                g_binds[g_nb_binds].guest = colon + 1;
                                g_binds[g_nb_binds].guest_len =
                                        strlen(colon + 1);
                                g_nb_binds++;
                        }
                        if (pair != NULL)
                                dbg("bind list truncated at %d entries",
                                    g_nb_binds);
                }
        }

        g_fake_id0 = getenv("NPROOT_FAKEID0") != NULL;

        init_real_all_once();
        dbg("shim active, root = %.*s, loader = %s, binds = %d, fake_id0 = %d",
            (int)g_root_len, g_root, g_loader ? g_loader : "(none)",
            g_nb_binds, g_fake_id0);
}

/* ------------------------------------------------------------------ */
/* fd syscalls                                                         */
/* ------------------------------------------------------------------ */

static mode_t va_mode(int flags, va_list ap)
{
        return (flags & (O_CREAT | O_TMPFILE)) ? va_arg(ap, mode_t) : 0;
}

int open(const char *path, int flags, ...)
{
        char buf[PATH_MAX];
        mode_t mode;
        va_list ap;

        init_real_all_once();
        va_start(ap, flags);
        mode = va_mode(flags, ap);
        va_end(ap);
        return real_open(xlate_follow(buf, sizeof(buf), path), flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
        char buf[PATH_MAX];
        mode_t mode;
        va_list ap;

        init_real_all_once();
        va_start(ap, flags);
        mode = va_mode(flags, ap);
        va_end(ap);
        return real_openat(dirfd, xlate_follow(buf, sizeof(buf), path),
                           flags, mode);
}

int creat(const char *path, mode_t mode)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_creat(xlate_follow(buf, sizeof(buf), path), mode);
}

#ifdef __GLIBC__
int open64(const char *path, int flags, ...)
{
        char buf[PATH_MAX];
        mode_t mode;
        va_list ap;

        init_real_all_once();
        va_start(ap, flags);
        mode = va_mode(flags, ap);
        va_end(ap);
        return real_open64(xlate_follow(buf, sizeof(buf), path), flags, mode);
}

int openat64(int dirfd, const char *path, int flags, ...)
{
        char buf[PATH_MAX];
        mode_t mode;
        va_list ap;

        init_real_all_once();
        va_start(ap, flags);
        mode = va_mode(flags, ap);
        va_end(ap);
        return real_openat64(dirfd, xlate_follow(buf, sizeof(buf), path),
                             flags, mode);
}

int creat64(const char *path, mode_t mode)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_creat64(xlate_follow(buf, sizeof(buf), path), mode);
}
#endif /* __GLIBC__ */

/* ------------------------------------------------------------------ */
/* stat family (statx is interposed on musl only -- see below)         */
/* ------------------------------------------------------------------ */

/* Rewrite ownership to root:0:0 when -0 emulation is on, so guest
 * software (dpkg, pacman, ...) sees the identity it asked proot for. */
static void fake_ids_stat(void *st, uid_t *uid, gid_t *gid)
{
        (void) st;
        if (g_fake_id0) {
                *uid = 0;
                *gid = 0;
        }
}

int stat(const char *path, struct stat *st)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_stat(xlate_follow(buf, sizeof(buf), path), st);
        if (rc == 0)
                fake_ids_stat(NULL, &st->st_uid, &st->st_gid);
        return rc;
}

int lstat(const char *path, struct stat *st)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_lstat(xlate(buf, sizeof(buf), path), st);
        if (rc == 0)
                fake_ids_stat(NULL, &st->st_uid, &st->st_gid);
        return rc;
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        if (flags & AT_SYMLINK_NOFOLLOW)
                rc = real_fstatat(dirfd, xlate(buf, sizeof(buf), path),
                                  st, flags);
        else
                rc = real_fstatat(dirfd, xlate_follow(buf, sizeof(buf), path),
                                  st, flags);
        if (rc == 0)
                fake_ids_stat(NULL, &st->st_uid, &st->st_gid);
        return rc;
}

#ifdef __GLIBC__
int stat64(const char *path, struct stat64 *st)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_stat64(xlate_follow(buf, sizeof(buf), path), st);
        if (rc == 0)
                fake_ids_stat(NULL, &st->st_uid, &st->st_gid);
        return rc;
}

int lstat64(const char *path, struct stat64 *st)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_lstat64(xlate(buf, sizeof(buf), path), st);
        if (rc == 0)
                fake_ids_stat(NULL, &st->st_uid, &st->st_gid);
        return rc;
}

int fstatat64(int dirfd, const char *path, struct stat64 *st, int flags)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        if (flags & AT_SYMLINK_NOFOLLOW)
                rc = real_fstatat64(dirfd, xlate(buf, sizeof(buf), path),
                                    st, flags);
        else
                rc = real_fstatat64(dirfd, xlate_follow(buf, sizeof(buf), path),
                                    st, flags);
        if (rc == 0)
                fake_ids_stat(NULL, &st->st_uid, &st->st_gid);
        return rc;
}
#endif /* __GLIBC__ */

#ifndef __GLIBC__
/* statx: musl guests expose ONE unversioned symbol and busybox plus
 * newer coreutils call it directly, so with no hook their absolute
 * paths hit the HOST filesystem while the very same file exec'ed
 * fine from PATH lookup (device log: "ls /usr/bin/apt-cdrom" ENOENT
 * next to a working apt-cdrom).  musl has no symbol versioning, so
 * defining statx here is safe; the glibc shim keeps it uninterposed
 * on purpose (an unversioned statx definition crashed BIND_NOW glibc
 * binaries at relocation, see the file header) and glibc guests reach
 * every stat through the hooked fstatat instead.  The buffer is
 * passed through untouched: only the path needs translating. */
int statx(int dirfd, const char *pathname, int flags,
          unsigned int mask, struct statx *statxbuf)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_statx(dirfd,
                          xlate_follow(buf, sizeof(buf), pathname),
                          flags, mask, statxbuf);
}
#endif /* !__GLIBC__ */

/* ------------------------------------------------------------------ */
/* access / metadata / directory ops                                   */
/* ------------------------------------------------------------------ */

int access(const char *path, int mode)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_access(xlate_follow(buf, sizeof(buf), path), mode);
        /* -0: pretend read/execute access exists, as the kernel would
         * allow it for root; write access stays honest.  */
        if (rc < 0 && g_fake_id0 && errno == EACCES &&
            (mode & R_OK) && !(mode & W_OK))
                return 0;
        return rc;
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_faccessat(dirfd, xlate_follow(buf, sizeof(buf), path),
                            mode, flags);
        if (rc < 0 && g_fake_id0 && errno == EACCES &&
            (mode & R_OK) && !(mode & W_OK))
                return 0;
        return rc;
}

#ifdef __GLIBC__
int faccessat2(int dirfd, const char *path, int mode, int flags)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_faccessat2(dirfd, xlate_follow(buf, sizeof(buf), path),
                             mode, flags);
        if (rc < 0 && g_fake_id0 && errno == EACCES &&
            (mode & R_OK) && !(mode & W_OK))
                return 0;
        return rc;
}
#endif

int unlink(const char *path)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_unlink(xlate_follow(buf, sizeof(buf), path));
}

int unlinkat(int dirfd, const char *path, int flags)
{
        char buf[PATH_MAX];

        init_real_all_once();
        if (flags & AT_REMOVEDIR)
                return real_unlinkat(dirfd, xlate(buf, sizeof(buf), path), flags);
        return real_unlinkat(dirfd, xlate_follow(buf, sizeof(buf), path), flags);
}

int rmdir(const char *path)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_rmdir(xlate(buf, sizeof(buf), path));
}

int mkdir(const char *path, mode_t mode)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_mkdir(xlate_follow(buf, sizeof(buf), path), mode);
}

int mkdirat(int dirfd, const char *path, mode_t mode)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_mkdirat(dirfd, xlate_follow(buf, sizeof(buf), path), mode);
}

/* -0: chmod/chown succeed even where the kernel would refuse (EPERM
 * only -- ENOENT and friends stay truthful, as in proot's fake_id0). */
int chmod(const char *path, mode_t mode)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_chmod(xlate_follow(buf, sizeof(buf), path), mode);
        if (rc < 0 && g_fake_id0 && errno == EPERM)
                return 0;
        return rc;
}

int fchmodat(int dirfd, const char *path, mode_t mode, int flags)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_fchmodat(dirfd, xlate_follow(buf, sizeof(buf), path),
                           mode, flags);
        if (rc < 0 && g_fake_id0 && errno == EPERM)
                return 0;
        return rc;
}

int fchmod(int fd, mode_t mode)
{
        int rc;

        init_real_all_once();
        rc = real_fchmod(fd, mode);
        if (rc < 0 && g_fake_id0 && errno == EPERM)
                return 0;
        return rc;
}

int chown(const char *path, uid_t owner, gid_t group)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_chown(xlate_follow(buf, sizeof(buf), path), owner, group);
        if (rc < 0 && g_fake_id0 && errno == EPERM)
                return 0;
        return rc;
}

int lchown(const char *path, uid_t owner, gid_t group)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        rc = real_lchown(xlate(buf, sizeof(buf), path), owner, group);
        if (rc < 0 && g_fake_id0 && errno == EPERM)
                return 0;
        return rc;
}

int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags)
{
        char buf[PATH_MAX];
        int rc;

        init_real_all_once();
        if (flags & AT_SYMLINK_NOFOLLOW)
                rc = real_fchownat(dirfd, xlate(buf, sizeof(buf), path),
                                   owner, group, flags);
        else
                rc = real_fchownat(dirfd, xlate_follow(buf, sizeof(buf), path),
                                   owner, group, flags);
        if (rc < 0 && g_fake_id0 && errno == EPERM)
                return 0;
        return rc;
}

int fchown(int fd, uid_t owner, gid_t group)
{
        int rc;

        init_real_all_once();
        rc = real_fchown(fd, owner, group);
        if (rc < 0 && g_fake_id0 && errno == EPERM)
                return 0;
        return rc;
}

int rename(const char *old, const char *new)
{
        char b1[PATH_MAX], b2[PATH_MAX];

        init_real_all_once();
        return real_rename(xlate_follow(b1, sizeof(b1), old),
                           xlate_follow(b2, sizeof(b2), new));
}

int renameat(int olddirfd, const char *old, int newdirfd, const char *new)
{
        char b1[PATH_MAX], b2[PATH_MAX];

        init_real_all_once();
        return real_renameat(olddirfd, xlate_follow(b1, sizeof(b1), old),
                             newdirfd, xlate_follow(b2, sizeof(b2), new));
}

#ifdef __GLIBC__
int renameat2(int olddirfd, const char *old, int newdirfd, const char *new,
              unsigned int flags)
{
        char b1[PATH_MAX], b2[PATH_MAX];

        init_real_all_once();
        return real_renameat2(olddirfd, xlate_follow(b1, sizeof(b1), old),
                              newdirfd, xlate_follow(b2, sizeof(b2), new),
                              flags);
}
#endif

int symlink(const char *target, const char *linkpath)
{
        char b1[PATH_MAX], b2[PATH_MAX];

        init_real_all_once();
        return real_symlink(xlate(b1, sizeof(b1), target),
                            xlate_follow(b2, sizeof(b2), linkpath));
}

int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
        char b1[PATH_MAX], b2[PATH_MAX];

        init_real_all_once();
        return real_symlinkat(xlate(b1, sizeof(b1), target), newdirfd,
                              xlate_follow(b2, sizeof(b2), linkpath));
}

int link(const char *old, const char *new)
{
        char b1[PATH_MAX], b2[PATH_MAX];

        init_real_all_once();
        return real_link(xlate_follow(b1, sizeof(b1), old),
                         xlate_follow(b2, sizeof(b2), new));
}

int linkat(int olddirfd, const char *old, int newdirfd, const char *new,
           int flags)
{
        char b1[PATH_MAX], b2[PATH_MAX];

        init_real_all_once();
        return real_linkat(olddirfd, xlate_follow(b1, sizeof(b1), old),
                           newdirfd, xlate_follow(b2, sizeof(b2), new), flags);
}

ssize_t readlink(const char *path, char *buf, size_t bufsz)
{
        char xb[PATH_MAX];

        init_real_all_once();
        return real_readlink(xlate(xb, sizeof(xb), path), buf, bufsz);
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsz)
{
        char xb[PATH_MAX];

        init_real_all_once();
        return real_readlinkat(dirfd, xlate(xb, sizeof(xb), path), buf, bufsz);
}

int truncate(const char *path, off_t len)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_truncate(xlate_follow(buf, sizeof(buf), path), len);
}

#ifdef __GLIBC__
int truncate64(const char *path, off_t len)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_truncate64(xlate_follow(buf, sizeof(buf), path), len);
}
#endif

int utimes(const char *path, const struct timeval tv[2])
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_utimes(xlate_follow(buf, sizeof(buf), path), tv);
}

int utimensat(int dirfd, const char *path, const struct timespec ts[2],
              int flags)
{
        char buf[PATH_MAX];

        init_real_all_once();
        if (flags & AT_SYMLINK_NOFOLLOW)
                return real_utimensat(dirfd, xlate(buf, sizeof(buf), path),
                                      ts, flags);
        return real_utimensat(dirfd, xlate_follow(buf, sizeof(buf), path),
                              ts, flags);
}

int mknod(const char *path, mode_t mode, dev_t dev)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_mknod(xlate_follow(buf, sizeof(buf), path), mode, dev);
}

int mknodat(int dirfd, const char *path, mode_t mode, dev_t dev)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_mknodat(dirfd, xlate_follow(buf, sizeof(buf), path),
                            mode, dev);
}

/* ------------------------------------------------------------------ */
/* stdio / dirent entry points: glibc calls openat(2) internally from  */
/* these, bypassing the PLT, so hooking them (and handing them an      */
/* already-translated path) is what makes ls(1), find(1), stdio work   */
/* ------------------------------------------------------------------ */

DIR *opendir(const char *name)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_opendir(xlate_follow(buf, sizeof(buf), name));
}

FILE *fopen(const char *path, const char *mode)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_fopen(xlate_follow(buf, sizeof(buf), path), mode);
}

#ifdef __GLIBC__
FILE *fopen64(const char *path, const char *mode)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_fopen64(xlate_follow(buf, sizeof(buf), path), mode);
}
#endif

FILE *freopen(const char *path, const char *mode, FILE *stream)
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_freopen(xlate_follow(buf, sizeof(buf), path), mode, stream);
}

int scandir(const char *dir, struct dirent ***namelist,
            int (*sel)(const struct dirent *),
            int (*cmp)(const struct dirent **, const struct dirent **))
{
        char buf[PATH_MAX];

        init_real_all_once();
        return real_scandir(xlate_follow(buf, sizeof(buf), dir), namelist,
                            sel, cmp);
}

#ifdef __GLIBC__
int scandir64(const char *dir, struct dirent64 ***namelist,
              int (*sel)(const struct dirent64 *),
              int (*cmp)(const struct dirent64 **, const struct dirent64 **))
{
        char buf[PATH_MAX];

        /* on LP64 glibc, dirent64 shares the layout of dirent */
        init_real_all_once();
        return real_scandir(xlate_follow(buf, sizeof(buf), dir),
                            (struct dirent ***)namelist,
                            (int (*)(const struct dirent *))sel,
                            (int (*)(const struct dirent **,
                                     const struct dirent **))cmp);
}
#endif

void *dlopen(const char *filename, int flags)
{
        char buf[PATH_MAX];
        void *h;

        init_real_all_once();
        h = real_dlopen(xlate(buf, sizeof(buf), filename), flags);
        /* NSS modules, locale plugins, language runtimes: anything
         * mapped AFTER the constructor carries unhardened stubs of
         * blocked numbers.  The walk is idempotent -- patched stubs no
         * longer match the movz patterns -- so a plain re-run is both
         * correct and cheap. */
        if (h != NULL && __atomic_load_n(&g_shield_armed,
                                         __ATOMIC_ACQUIRE))
                shield_harden_maps();
        return h;
}

/* ------------------------------------------------------------------ */
/* getcwd: present guest-relative cwd                                  */
/* ------------------------------------------------------------------ */

char *getcwd(char *buf, size_t size)
{
        char *res;

        init_real_all_once();
        res = real_getcwd(buf, size);
        if (res != NULL && g_root_len > 0 &&
            strncmp(res, g_root, g_root_len) == 0 && res[g_root_len] == '/') {
                size_t rest = strlen(res) - g_root_len; /* keep the '/' */
                memmove(res, res + g_root_len, rest + 1);
        }
        return res;
}

/* chdir was the one path-taking syscall nobody interposed: "cd /" in
 * the guest shell therefore landed on the HOST root -- the device log
 * showed an Android /system, a Permission-denied / and /data, and a
 * "cd /root" failing because ANDROID has no /root.  Route guest
 * absolute paths through the same translation open(2) uses; relative
 * paths keep resolving against the (already host-side) cwd, and
 * fchdir takes an fd with no path at all. */
int chdir(const char *path)
{
        char buf[PATH_MAX];

        init_real_all_once();
        if (path != NULL && path[0] == '/')
                path = xlate(buf, sizeof(buf), path);
        return real_chdir(path);
}

/* ------------------------------------------------------------------ */
/* identity family: proot -0 emulation                                  */
/* ------------------------------------------------------------------ */

uid_t getuid(void)
{
        init_real_all_once();
        return g_fake_id0 ? 0 : real_getuid();
}

uid_t geteuid(void)
{
        init_real_all_once();
        return g_fake_id0 ? 0 : real_geteuid();
}

gid_t getgid(void)
{
        init_real_all_once();
        return g_fake_id0 ? 0 : real_getgid();
}

gid_t getegid(void)
{
        init_real_all_once();
        return g_fake_id0 ? 0 : real_getegid();
}

#define FAKE_ID0_SET1(name, type)                                   \
        int name(type id)                                            \
        {                                                            \
                init_real_all_once();                                \
                return g_fake_id0 ? 0 : real_##name(id);             \
        }
#define FAKE_ID0_SET2(name, type)                                   \
        int name(type a, type b)                                     \
        {                                                            \
                init_real_all_once();                                \
                return g_fake_id0 ? 0 : real_##name(a, b);           \
        }
#define FAKE_ID0_SET3(name, type)                                   \
        int name(type a, type b, type c)                             \
        {                                                            \
                init_real_all_once();                                \
                return g_fake_id0 ? 0 : real_##name(a, b, c);        \
        }

FAKE_ID0_SET1(setuid, uid_t)
FAKE_ID0_SET1(setgid, gid_t)
FAKE_ID0_SET1(seteuid, uid_t)
FAKE_ID0_SET1(setegid, gid_t)
FAKE_ID0_SET2(setreuid, uid_t)
FAKE_ID0_SET2(setregid, gid_t)
FAKE_ID0_SET3(setresuid, uid_t)
FAKE_ID0_SET3(setresgid, gid_t)

/* ------------------------------------------------------------------ */
/* execve: resolve shebang + PT_INTERP + guest symlinks, then reroute  */
/* through the guest loader so chained execs stay translated           */
/* ------------------------------------------------------------------ */

/* Does the host-side ELF file request a dynamic loader (PT_INTERP)?
 * On success the interpreter string is copied into @interp. */
static int elf_interp(const char *host_path, char *interp, size_t isz,
                      int *is_elf)
{
        unsigned char ehdr[64];
        unsigned char ph[56];
        uint64_t phoff, ioff, ifilesz;
        uint16_t phentsize, phnum;
        int fd, i, found;

        interp[0] = '\0';
        *is_elf = 0;
        fd = real_open(host_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -1;      /* propagate the error via execve */
        if (pread(fd, ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
                close(fd);
                return 0;       /* not an ELF (scripts handled elsewhere) */
        }
        if (memcmp(ehdr, "\x7f""ELF", 4) != 0) {
                close(fd);
                return 0;
        }
        *is_elf = (ehdr[4] == 2);       /* ELFCLASS64 only in the prototype */
        if (ehdr[4] != 2) {
                close(fd);
                return 0;
        }
        memcpy(&phoff, ehdr + 32, 8);
        memcpy(&phentsize, ehdr + 54, 2);
        memcpy(&phnum, ehdr + 56, 2);
        if (phentsize != 56 || phnum == 0 || phnum > 128) {
                close(fd);
                return 0;
        }
        found = 0;
        for (i = 0; i < phnum && !found; i++) {
                uint32_t ptype;
                if (pread(fd, ph, sizeof(ph), (off_t)phoff + (off_t)i * phentsize)
                    != sizeof(ph))
                        break;
                memcpy(&ptype, ph, 4);
                if (ptype == 3) { /* PT_INTERP */
                        memcpy(&ioff, ph + 8, 8);
                        memcpy(&ifilesz, ph + 32, 8);
                        if (ifilesz > isz - 1)
                                ifilesz = isz - 1;
                        if (ifilesz > 0 &&
                            pread(fd, interp, ifilesz, (off_t)ioff)
                                == (ssize_t)ifilesz)
                                interp[ifilesz] = '\0';
                        else
                                interp[0] = '\0';
                        found = 1;
                }
        }
        close(fd);
        return found;
}

/* Does the interpreter belong to the same libc family as the guest
 * loader?  Foreign-family interpreters (Android's bionic
 * /system/bin/linker64, a host tool bound into the guest) cannot be
 * loaded by the guest loader: rerouting them ended in relocation
 * errors against the wrong libc.  They must run natively instead --
 * exactly what the ptrace backend does with host binaries. */
static int interp_matches_loader(const char *interp)
{
        int musl_interp = strstr(interp, "ld-musl") != NULL;
        int glibc_interp = strstr(interp, "ld-linux") != NULL ||
                           strstr(interp, "ld64.so") != NULL;

        return g_guest_is_musl ? musl_interp : glibc_interp;
}

/* Parse "#!/interp [arg]" and report whether the file is a script.  */
static int resolve_shebang(const char *prog, char *interp, size_t isz,
                           char *iarg, size_t asz)
{
        char head[256];
        int fd;
        ssize_t n;
        char *nl, *sp;

        fd = real_open(prog, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -1;
        n = pread(fd, head, sizeof(head) - 1, 0);
        close(fd);
        if (n < 2 || head[0] != '#' || head[1] != '!')
                return 0;
        head[n] = '\0';
        nl = memchr(head, '\n', (size_t)n);
        if (nl != NULL)
                *nl = '\0';
        sp = head + 2;
        while (*sp == ' ' || *sp == '\t')
                sp++;
        if (*sp == '\0')
                return 0;
        nl = sp;
        while (*nl != '\0' && *nl != ' ' && *nl != '\t')
                nl++;
        if (*nl != '\0') {
                char *a = nl + 1;
                *nl = '\0';
                while (*a == ' ')
                        a++;
                snprintf(iarg, asz, "%s", a);
        } else {
                iarg[0] = '\0';
        }
        snprintf(interp, isz, "%s", sp);
        return 1;
}

static int exec_loader_route(const char *prog, char *const argv[],
                             char *const envp[])
{
        char **navv;
        int argc, i, saved;
        int n = 0;
        int use_argv0;
        const char *applet = NULL;

        for (argc = 0; argv[argc] != NULL; argc++)
                ;
        navv = malloc(sizeof(char *) * (size_t)(argc + 5));
        if (navv == NULL) {
                errno = ENOMEM;
                return -1;
        }
        navv[n++] = (char *)g_loader;

        use_argv0 = (strstr(g_loader, "ld-linux") != NULL && argv[0] != NULL);
        if (use_argv0) {
                /* glibc loader: restore the guest-visible argv[0] */
                navv[n++] = (char *)"--argv0";
                navv[n++] = argv[0];
        } else if (strcmp(base_name_of(prog), "busybox") == 0 &&
                   argv[0] != NULL &&
                   strcmp(base_name_of(argv[0]), "busybox") != 0) {
                /* busybox dispatch: the requested applet (basename of
                 * the original guest path) becomes busybox's argv[1] */
                applet = base_name_of(argv[0]);
        }
        navv[n++] = (char *)prog;
        if (applet != NULL)
                navv[n++] = (char *)applet;
        for (i = 1; i < argc; i++)
                navv[n++] = argv[i];
        navv[n] = NULL;

        dbg("exec via loader: %s %s", g_loader, prog);
        saved = errno;
        real_execve(g_loader, navv, envp);
        saved = errno;          /* execve failed; report through */
        free(navv);
        errno = saved;
        return -1;
}

/* Run a foreign-family (host) binary natively, like the ptrace
 * backend would: without our shim in LD_PRELOAD (it is built for the
 * guest libc, and the host binary's loader would preload it anyway --
 * the extracted shim's name does not matter, so drop the whole
 * variable; the launcher already replaced any user preload with our
 * shim) and without the guest library search path (host-namespace
 * dirs that would poison the host loader's search). */
static int exec_native_route(const char *prog, char *const argv[],
                             char *const envp[])
{
        char **nenv;
        int cnt, i, n, saved;

        for (cnt = 0; envp[cnt] != NULL; cnt++)
                ;
        nenv = malloc(sizeof(char *) * (size_t)(cnt + 1));
        if (nenv == NULL)
                return real_execve(prog, argv, envp);   /* best effort */
        n = 0;
        for (i = 0; i < cnt; i++) {
                if (strncmp(envp[i], "LD_PRELOAD=", 11) == 0)
                        continue;
                if (strncmp(envp[i], "LD_LIBRARY_PATH=", 16) == 0)
                        continue;
                nenv[n++] = envp[i];
        }
        nenv[n] = NULL;
        dbg("exec native (foreign interp): %s", prog);
        i = real_execve(prog, argv, nenv);
        saved = errno;
        free(nenv);
        errno = saved;
        return i;
}

static void nproot_unblock_sigsys(void);

static int do_execve(const char *path, char *const argv[], char *const envp[])
{
        static __thread char *nargv[4096];
        static __thread char pbuf[PATH_MAX];
        const char *prog;
        char interp[PATH_MAX], iarg[64];
        char *const *rest = (char *const *)argv;
        int is_elf, dyn;
        int depth;

        /* The new image inherits this mask through execve: leave SIGSYS
         * blocked here and the guest starts one blocked-window trap
         * away from a silent death, with its guard still unarmed. */
        nproot_unblock_sigsys();

        if (g_loader == NULL) {
                char buf[PATH_MAX];
                return real_execve(xlate_follow(buf, sizeof(buf), path),
                                   argv, envp);
        }

        prog = xlate(pbuf, sizeof(pbuf), path);
        if (prog == NULL || prog[0] != '/')
                return real_execve(path, argv, envp);
        if (prog != pbuf)
                snprintf(pbuf, sizeof(pbuf), "%s", prog);
        prog = pbuf;

        /* resolve guest symlinks first: applet/loader links carry
         * guest-absolute targets the host kernel cannot follow */
        resolve_guest_links(pbuf, sizeof(pbuf));
        prog = pbuf;
        dbg("exec hook: translated to %s", prog);

        for (depth = 0; depth < 4; depth++) {
                int rc = resolve_shebang(prog, interp, sizeof(interp),
                                         iarg, sizeof(iarg));
                if (rc < 0)
                        return real_execve(prog, rest, envp);   /* ENOENT etc */
                if (rc == 0)
                        goto not_script;

                /* Rebuild argv: interpreter [optional-arg] script rest... */
                {
                        int n = 0, i, first;

                        if (iarg[0] != '\0' && depth == 0)
                                nargv[n++] = iarg;
                        first = (depth == 0) ? 1 : 0;
                        for (i = first; rest[i] != NULL && n < 4090; i++)
                                nargv[n++] = rest[i];
                        nargv[n] = NULL;
                        rest = nargv;

                        if (interp[0] == '/')
                                reroot_guest_abs(pbuf, sizeof(pbuf), interp);
                        else
                                snprintf(pbuf, sizeof(pbuf), "%s", interp);
                        resolve_guest_links(pbuf, sizeof(pbuf));
                        prog = pbuf;
                }
        }
not_script:
        dyn = elf_interp(prog, interp, sizeof(interp), &is_elf);
        dbg("exec hook: %s is_elf=%d dyn=%d interp=[%s]", prog, is_elf,
            dyn, interp);
        if (is_elf && dyn) {
                /* an unreadable interp keeps the old reroute behavior
                 * instead of failing differently than the kernel */
                if (interp[0] == '\0' || interp_matches_loader(interp))
                        return exec_loader_route(prog, rest, envp);
                return exec_native_route(prog, rest, envp);
        }
        return real_execve(prog, rest, envp);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
        init_real_all_once();
        return do_execve(path, argv, envp);
}

int execv(const char *path, char *const argv[])
{
        init_real_all_once();
        return do_execve(path, argv, environ);
}

int execvp(const char *file, char *const argv[])
{
        char buf[PATH_MAX];
        const char *p;

        init_real_all_once();
        if (file != NULL && file[0] == '/')
                return do_execve(file, argv, environ);

        /* search the guest PATH ourselves; fall back to common dirs */
        p = getenv("PATH");
        if (p != NULL) {
                char pathbuf[PATH_MAX];
                char *save = NULL;

                snprintf(pathbuf, sizeof(pathbuf), "%s", p);
                for (char *dir = strtok_r(pathbuf, ":", &save); dir != NULL;
                     dir = strtok_r(NULL, ":", &save)) {
                        if (dir[0] != '/')
                                continue;
                        snprintf(buf, sizeof(buf), "%s/%s", dir, file);
                        if (access(buf, X_OK) == 0)
                                return do_execve(buf, argv, environ);
                }
        }
        {
                static const char *bindirs[] =
                        { "/bin", "/usr/bin", "/sbin", "/usr/sbin", NULL };
                int i;

                for (i = 0; bindirs[i] != NULL; i++) {
                        snprintf(buf, sizeof(buf), "%s/%s", bindirs[i], file);
                        if (access(buf, X_OK) == 0)
                                return do_execve(buf, argv, environ);
                }
        }
        errno = ENOENT;
        return -1;
}

/* ------------------------------------------------------------------ */
/* process-creation windows: bracket fork/posix_spawn in the debug log */
/* ------------------------------------------------------------------ */

/* glibc masks every signal around the clone(2) inside fork() and
 * posix_spawn(), and force_sig() resets a blocked SIGSYS disposition
 * to SIG_DFL BEFORE delivering -- a trapped syscall in that window
 * kills the process silently.  These wrappers add no behavior; they
 * only mark the window so a death log ends between "window enter" and
 * "window exit rc=..." and the search narrows to the fork/spawn
 * internals.  vsnprintf under g_debug is safe here: the guest is
 * single-threaded at these call sites, so no malloc lock can be held. */

pid_t fork(void)
{
        pid_t rc;

        init_real_all_once();
        if (g_debug)
                dbg("process window enter: fork");
        if (real_fork == NULL) {
                errno = ENOSYS;
                return -1;
        }
        rc = real_fork();
        /* both sides: the child may have inherited a mid-window mask,
         * and the parent's own restore must never leave SIGSYS set */
        nproot_unblock_sigsys();
        if (g_debug)
                dbg("process window exit: fork rc=%d", (int)rc);
        return rc;
}

int posix_spawn(pid_t *pid, const char *path,
                const posix_spawn_file_actions_t *acts,
                const posix_spawnattr_t *attr,
                char *const argv[], char *const envp[])
{
        int rc;

        init_real_all_once();
        if (g_debug)
                dbg("process window enter: posix_spawn %s", path);
        rc = real_posix_spawn(pid, path, acts, attr, argv, envp);
        nproot_unblock_sigsys();
        if (g_debug)
                dbg("process window exit: posix_spawn rc=%d", rc);
        return rc;
}

int posix_spawnp(pid_t *pid, const char *file,
                 const posix_spawn_file_actions_t *acts,
                 const posix_spawnattr_t *attr,
                 char *const argv[], char *const envp[])
{
        int rc;

        init_real_all_once();
        if (g_debug)
                dbg("process window enter: posix_spawnp %s", file);
        rc = real_posix_spawnp(pid, file, acts, attr, argv, envp);
        nproot_unblock_sigsys();
        if (g_debug)
                dbg("process window exit: posix_spawnp rc=%d", rc);
        return rc;
}

/* ------------------------------------------------------------------ */
/* SIGSYS must never sit blocked: force_sig() then resets the          */
/* disposition to SIG_DFL and the next trap kills silently             */
/* ------------------------------------------------------------------ */

#ifndef SYS_rt_sigprocmask
#if defined(__x86_64__)
#define SYS_rt_sigprocmask 14
#elif defined(__aarch64__)
#define SYS_rt_sigprocmask 135
#endif
#endif

/* Raw kernel ABI: a libc sigset_t is misread across libc families,
 * and the guard's own rt_sigaction already goes through the same
 * 8-byte-mask convention.  Silent by design -- it runs on every
 * fork/spawn/exec and merely re-asserts the only invariant the
 * seccomp guard needs: SIGSYS deliverable. */
static void nproot_unblock_sigsys(void)
{
        unsigned long mask = 1UL << (SIGSYS - 1);
        struct {
                void *handler;
                unsigned long flags;
                void (*restorer)(void);
                unsigned long mask;
        } old;
        long r;

        syscall(SYS_rt_sigprocmask, SIG_UNBLOCK, &mask, NULL,
                sizeof(mask));
        /* Self-heal: force_sig() may already have reset the guard to
         * SIG_DFL during an all-blocked window -- invisible, since the
         * handler never ran.  A reset also leaves any queued SIGSYS
         * pending as a SIG_DFL kill that fires the moment the mask
         * clears.  Re-arming here makes that pending signal deliver
         * to the handler instead: the disposition is read at delivery
         * time, not at queue time. */
        memset(&old, 0, sizeof(old));
        r = syscall(SYS_rt_sigaction, SIGSYS, 0UL, &old,
                    sizeof(unsigned long));
        if (r == 0 && old.handler != (void *)seccomp_sigsys_emulate)
                ksigaction(SIGSYS, seccomp_sigsys_emulate,
                           KSA_SIGINFO | KSA_NODEFER);
}

/* Programs block signals for good reasons (bash around command
 * substitution, runtimes around thread creation); glibc does the same
 * inside its own fork/spawn windows.  A seccomp trap delivered in any
 * such window is force_sig()ed to SIG_DFL first -- silent death, no
 * handler, no log.  Interpose the public mask entry points and strip
 * SIGSYS from every block request.  glibc-internal callers bypass the
 * PLT, which is fine: the census-verified stub hardening covers their
 * syscall sites, and the fork/spawn wrappers above unblock after
 * every window.  Each actual strip is logged at debug level, so the
 * next silent-death log names the would-be blocker for free.
 * sigdelset/memcmp are pure memory arithmetic: async-signal-safe. */

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
        sigset_t stripped;

        init_real_all_once();
        if (set != NULL && real_sigprocmask != NULL &&
            (how == SIG_BLOCK || how == SIG_SETMASK)) {
                memcpy(&stripped, set, sizeof(stripped));
                sigdelset(&stripped, SIGSYS);
                if (memcmp(&stripped, set, sizeof(stripped)) != 0) {
                        dbg("sigprocmask: stripped SIGSYS (how=%d)",
                            how);
                        set = &stripped;
                }
        }
        if (real_sigprocmask == NULL) {
                errno = ENOSYS;
                return -1;
        }
        return real_sigprocmask(how, set, oldset);
}

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset)
{
        sigset_t stripped;

        init_real_all_once();
        if (set != NULL && real_pthread_sigmask != NULL &&
            (how == SIG_BLOCK || how == SIG_SETMASK)) {
                memcpy(&stripped, set, sizeof(stripped));
                sigdelset(&stripped, SIGSYS);
                if (memcmp(&stripped, set, sizeof(stripped)) != 0) {
                        dbg("pthread_sigmask: stripped SIGSYS "
                            "(how=%d)", how);
                        set = &stripped;
                }
        }
        if (real_pthread_sigmask == NULL) {
                errno = ENOSYS;
                return -1;
        }
        return real_pthread_sigmask(how, set, oldset);
}

/* ------------------------------------------------------------------ */
/* The generic syscall() door: here x8/w8 comes from a register, so no */
/* static matcher can harden the site -- interpose the symbol instead. */
/* ------------------------------------------------------------------ */

/* The guard's own raw calls (rt_sigaction / rt_sigprocmask / the
 * sigreturn stub) must never route back into this door: always let
 * the signal-management numbers through, armed or not. */
static int syscall_always_raw(long nr)
{
#if defined(__x86_64__)
        return nr == 13 || nr == 14 || nr == 15;
#elif defined(__aarch64__)
        return nr == 134 || nr == 135 || nr == 139;
#else
        return 0;
#endif
}

long syscall(long number, ...)
{
        va_list ap;
        long a[6], i;

        init_real_all_once();
        if (real_syscall == NULL) {
                errno = ENOSYS;
                return -1;
        }
        /* Census probes run through this very symbol BEFORE the shield
         * arms (shield_mark sets the flag only after a verified list
         * exists), so arming the door cannot starve the census. */
        if (__atomic_load_n(&g_shield_armed, __ATOMIC_ACQUIRE) &&
            !syscall_always_raw(number) &&
            shield_is_blocked((unsigned)number)) {
                dbg("syscall(%ld) denied at the generic door "
                    "(blocked nr)", number);
                errno = ENOSYS;
                return -1;
        }
        va_start(ap, number);
        for (i = 0; i < 6; i++)
                a[i] = va_arg(ap, long);
        va_end(ap);
        return real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}
