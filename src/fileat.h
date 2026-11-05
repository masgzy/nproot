/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * fileat.h - prototypes for the legacy-syscall redirections in
 * fileat_wrap.c.  The GNUmakefile compiles every object with
 * -Daccess=nproot_access etc., so plain calls to access(2), unlink(2),
 * mkdir(2), ... land here and are issued through the *at/modern
 * syscall numbers (Android's app filter traps the legacy family and
 * the launcher has no SIGSYS guard).  See fileat_wrap.c.
 */

#ifndef FILEAT_H
#define FILEAT_H

#include <sys/types.h>
#include <sys/stat.h>

int nproot_access(const char *path, int mode);
int nproot_unlink(const char *path);
int nproot_rmdir(const char *path);
int nproot_mkdir(const char *path, mode_t mode);
int nproot_rename(const char *oldpath, const char *newpath);
int nproot_chmod(const char *path, mode_t mode);
int nproot_symlink(const char *target, const char *linkpath);
int nproot_pipe(int fds[2]);
int nproot_stat(const char *path, struct stat *buf);
int nproot_lstat(const char *path, struct stat *buf);

/* Only for fork sites whose child does plain syscalls + _exit (or
 * execs right away, where the fresh libc init re-establishes the
 * TCB): skips musl's fork-internal bookkeeping.  See fileat_wrap.c. */
pid_t nproot_fork(void);

#endif /* FILEAT_H */
