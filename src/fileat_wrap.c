/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * fileat_wrap.c - compile-time redirection of the legacy file syscalls
 * to their *at(2) equivalents.
 *
 * Android's app seccomp filter traps the whole legacy family --
 * access(21), pipe(22), rename(82), mkdir(83), rmdir(84), creat(85),
 * link(86), unlink(87), symlink(88), chmod(90), chown(92) -- because
 * bionic only ever issues the *at/modern forms.  Any nproot code
 * running OUTSIDE the shim (the static launcher carries no SIGSYS
 * guard) died instantly on them: the AVD showed the launcher vanish
 * before its first log line, at its very first access(2).
 *
 * The GNUmakefile compiles every object with
 *   -Daccess=nproot_access -Dunlink=... (see FILEAT_DEFS)
 * which renames the libc declarations and our call sites alike, so
 * the token-level remap is declaration-safe.  (A link-time
 * --wrap=access was tried first and silently failed: ld does not
 * wrap versioned undefined symbols like access@GLIBC_2.2.5.)
 * Semantics are identical on every Linux, so the remap applies
 * unconditionally (the regular CI exercises it).
 */
#define _GNU_SOURCE
#include "fileat.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>       /* SIGCHLD */
#include <unistd.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif

#ifndef SYS_faccessat
#if defined(__x86_64__)
#define SYS_faccessat 269
#elif defined(__aarch64__)
#define SYS_faccessat 48
#endif
#endif
#ifndef SYS_unlinkat
#if defined(__x86_64__)
#define SYS_unlinkat 263
#elif defined(__aarch64__)
#define SYS_unlinkat 35
#endif
#endif
#ifndef SYS_mkdirat
#if defined(__x86_64__)
#define SYS_mkdirat 258
#elif defined(__aarch64__)
#define SYS_mkdirat 34
#endif
#endif
#ifndef SYS_renameat
#if defined(__x86_64__)
#define SYS_renameat 264
#elif defined(__aarch64__)
#define SYS_renameat 38
#endif
#endif
#ifndef SYS_fchmodat
#if defined(__x86_64__)
#define SYS_fchmodat 268
#elif defined(__aarch64__)
#define SYS_fchmodat 53
#endif
#endif
#ifndef SYS_symlinkat
#if defined(__x86_64__)
#define SYS_symlinkat 266
#elif defined(__aarch64__)
#define SYS_symlinkat 36
#endif
#endif
#ifndef SYS_pipe2
#if defined(__x86_64__)
#define SYS_pipe2 293
#elif defined(__aarch64__)
#define SYS_pipe2 59
#endif
#endif
#ifndef SYS_NEWFSTATAT
#if defined(__x86_64__)
#define SYS_NEWFSTATAT 262
#elif defined(__aarch64__)
#define SYS_NEWFSTATAT 79
#endif
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef NPROOT_SYS_CLONE
#if defined(__x86_64__)
#define NPROOT_SYS_CLONE 56
#elif defined(__aarch64__)
#define NPROOT_SYS_CLONE 220
#endif
#endif

int nproot_access(const char *path, int mode)
{
        return (int)syscall(SYS_faccessat, (unsigned long)AT_FDCWD,
                            path, mode, 0UL);
}

int nproot_unlink(const char *path)
{
        return (int)syscall(SYS_unlinkat, (unsigned long)AT_FDCWD,
                            path, 0UL);
}

int nproot_rmdir(const char *path)
{
        return (int)syscall(SYS_unlinkat, (unsigned long)AT_FDCWD,
                            path, (unsigned long)AT_REMOVEDIR);
}

int nproot_mkdir(const char *path, mode_t mode)
{
        return (int)syscall(SYS_mkdirat, (unsigned long)AT_FDCWD,
                            path, (unsigned long)mode);
}

int nproot_rename(const char *oldpath, const char *newpath)
{
        return (int)syscall(SYS_renameat, (unsigned long)AT_FDCWD,
                            oldpath, (unsigned long)AT_FDCWD, newpath);
}

int nproot_chmod(const char *path, mode_t mode)
{
        return (int)syscall(SYS_fchmodat, (unsigned long)AT_FDCWD,
                            path, (unsigned long)mode, 0UL);
}

int nproot_symlink(const char *target, const char *linkpath)
{
        return (int)syscall(SYS_symlinkat, target,
                            (unsigned long)AT_FDCWD, linkpath);
}

int nproot_pipe(int fds[2])
{
        /* pipe(2) is trapped on Android 15 x86_64; pipe2(fds, 0) is
         * what bionic itself uses and is allowlisted. */
        return (int)syscall(SYS_pipe2, fds, 0UL);
}

/* musl maps stat/lstat to the LEGACY syscall numbers on x86_64
 * (SYS_stat 4 / SYS_lstat 6); the AVD autopsy caught the launcher
 * dying at lstat("/dev") -- nr 6, TRAP-class.  Route both through
 * newfstatat (the only form bionic uses, hence allowlisted). */
int nproot_stat(const char *path, struct stat *buf)
{
        return (int)syscall(SYS_NEWFSTATAT, (unsigned long)AT_FDCWD,
                            path, buf, 0UL);
}

int nproot_lstat(const char *path, struct stat *buf)
{
        return (int)syscall(SYS_NEWFSTATAT, (unsigned long)AT_FDCWD,
                            path, buf, (unsigned long)AT_SYMLINK_NOFOLLOW);
}

/* musl's fork(3) issues the legacy SYS_fork (nr 57, TRAP-class on
 * Android 15 x86_64).  A raw clone(SIGCHLD) is a plain COW fork.
 * Only for fork sites whose child does plain syscalls + _exit: it
 * skips libc-internal fork bookkeeping (the child's cached tid). */
pid_t nproot_fork(void)
{
        return (pid_t)syscall(NPROOT_SYS_CLONE, (unsigned long)SIGCHLD,
                              0UL, 0UL, 0UL, 0UL, 0UL);
}
