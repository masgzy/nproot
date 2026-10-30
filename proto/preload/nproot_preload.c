/* SPDX-License-Identifier: GPL-2.0-or-later */
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
 *     (with --argv0 on glibc, and busybox applet insertion on musl).
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
 * execve reroute), NPROOT_DEBUG (log translations to stderr).
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static ssize_t (*real_readlink)(const char *, char *, size_t);

/* ------------------------------------------------------------------ */
/* state                                                               */
/* ------------------------------------------------------------------ */

static const char *g_root;	/* NPROOT_ROOT, no trailing slash */
static size_t g_root_len;
static const char *g_loader;	/* NPROOT_LOADER or NULL */
static int g_debug;

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

/* Translate a guest path into a host path.  Relative paths and paths
 * that are already inside the rootfs are returned untouched.  */
static const char *xlate(char *buf, size_t bufsz, const char *path)
{
	if (path == NULL || path[0] != '/')
		return path;
	if (g_root_len > 0 && strncmp(path, g_root, g_root_len) == 0 &&
	    (path[g_root_len] == '/' || path[g_root_len] == '\0'))
		return path;	/* already translated (avoids loops) */
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
			snprintf(hostpath, sz, "%s%s", g_root, target);
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
 * returns EINVAL for regular files.  */
static const char *xlate_follow(char *buf, size_t bufsz, const char *path)
{
	if (path == NULL || path[0] != '/')
		return path;
	path = xlate(buf, bufsz, path);
	resolve_guest_links(buf, bufsz);
	return buf;
}

/* ------------------------------------------------------------------ */
/* real function pointers + lazy resolution                            */
/* ------------------------------------------------------------------ */

static int	(*real_open)(const char *, int, ...);
static int	(*real_openat)(int, const char *, int, ...);
static int	(*real_creat)(const char *, mode_t);
static int	(*real_stat)(const char *, struct stat *);
static int	(*real_lstat)(const char *, struct stat *);
static int	(*real_fstatat)(int, const char *, struct stat *, int);
static int	(*real_access)(const char *, int);
static int	(*real_faccessat)(int, const char *, int, int);
static int	(*real_unlink)(const char *);
static int	(*real_unlinkat)(int, const char *, int);
static int	(*real_rmdir)(const char *);
static int	(*real_mkdir)(const char *, mode_t);
static int	(*real_mkdirat)(int, const char *, mode_t);
static int	(*real_chmod)(const char *, mode_t);
static int	(*real_fchmodat)(int, const char *, mode_t, int);
static int	(*real_chown)(const char *, uid_t, gid_t);
static int	(*real_lchown)(const char *, uid_t, gid_t);
static int	(*real_fchownat)(int, const char *, uid_t, gid_t, int);
static int	(*real_rename)(const char *, const char *);
static int	(*real_renameat)(int, const char *, int, const char *);
static int	(*real_symlink)(const char *, const char *);
static int	(*real_symlinkat)(const char *, int, const char *);
static int	(*real_link)(const char *, const char *);
static int	(*real_linkat)(int, const char *, int, const char *, int);
static ssize_t	(*real_readlink)(const char *, char *, size_t);
static ssize_t	(*real_readlinkat)(int, const char *, char *, size_t);
static int	(*real_truncate)(const char *, off_t);
static int	(*real_utimes)(const char *, const struct timeval *);
static int	(*real_utimensat)(int, const char *, const struct timespec *, int);
static int	(*real_mknod)(const char *, mode_t, dev_t);
static int	(*real_mknodat)(int, const char *, mode_t, dev_t);
static DIR	*(*real_opendir)(const char *);
static FILE	*(*real_fopen)(const char *, const char *);
static FILE	*(*real_freopen)(const char *, const char *, FILE *);
static int	(*real_scandir)(const char *, struct dirent ***,
				int (*)(const struct dirent *),
				int (*)(const struct dirent **,
					const struct dirent **));
static void	*(*real_dlopen)(const char *, int);
static char	*(*real_getcwd)(char *, size_t);
static int	(*real_execve)(const char *, char *const [], char *const []);
static int	(*real_execv)(const char *, char *const []);
static int	(*real_execvp)(const char *, char *const []);

/* 64-bit fcntl/stdio aliases exist on both libcs (musl declares the
 * plain _64 functions too); the struct stat64 variants are glibc-only. */
static int	(*real_open64)(const char *, int, ...);
static int	(*real_openat64)(int, const char *, int, ...);
static int	(*real_creat64)(const char *, mode_t);
static int	(*real_truncate64)(const char *, off_t);
static FILE	*(*real_fopen64)(const char *, const char *);
#ifdef __GLIBC__
static int	(*real_stat64)(const char *, struct stat64 *);
static int	(*real_lstat64)(const char *, struct stat64 *);
static int	(*real_fstatat64)(int, const char *, struct stat64 *, int);
static int	(*real_renameat2)(int, const char *, int, const char *, unsigned);
static int	(*real_faccessat2)(int, const char *, int, int);
#endif

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
	real_execve = dlsym(RTLD_NEXT, "execve");
	real_execv = dlsym(RTLD_NEXT, "execv");
	real_execvp = dlsym(RTLD_NEXT, "execvp");
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
	if (g_root == NULL) {
		/* Not launched by nproot-lite; stay inert.  */
		g_root = none;
		g_root_len = 0;
		return;
	}
	g_root_len = strlen(g_root);
	while (g_root_len > 1 && g_root[g_root_len - 1] == '/')
		g_root_len--;	/* normalize trailing slash */

	init_real_all_once();
	dbg("shim active, root = %.*s, loader = %s",
	    (int)g_root_len, g_root, g_loader ? g_loader : "(none)");
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
/* stat family (statx deliberately NOT interposed -- see file header)  */
/* ------------------------------------------------------------------ */

int stat(const char *path, struct stat *st)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_stat(xlate_follow(buf, sizeof(buf), path), st);
}

int lstat(const char *path, struct stat *st)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_lstat(xlate(buf, sizeof(buf), path), st);
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
	char buf[PATH_MAX];

	init_real_all_once();
	if (flags & AT_SYMLINK_NOFOLLOW)
		return real_fstatat(dirfd, xlate(buf, sizeof(buf), path),
				    st, flags);
	return real_fstatat(dirfd, xlate_follow(buf, sizeof(buf), path),
			    st, flags);
}

#ifdef __GLIBC__
int stat64(const char *path, struct stat64 *st)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_stat64(xlate_follow(buf, sizeof(buf), path), st);
}

int lstat64(const char *path, struct stat64 *st)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_lstat64(xlate(buf, sizeof(buf), path), st);
}

int fstatat64(int dirfd, const char *path, struct stat64 *st, int flags)
{
	char buf[PATH_MAX];

	init_real_all_once();
	if (flags & AT_SYMLINK_NOFOLLOW)
		return real_fstatat64(dirfd, xlate(buf, sizeof(buf), path),
				      st, flags);
	return real_fstatat64(dirfd, xlate_follow(buf, sizeof(buf), path),
			      st, flags);
}
#endif /* __GLIBC__ */

/* ------------------------------------------------------------------ */
/* access / metadata / directory ops                                   */
/* ------------------------------------------------------------------ */

int access(const char *path, int mode)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_access(xlate_follow(buf, sizeof(buf), path), mode);
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_faccessat(dirfd, xlate_follow(buf, sizeof(buf), path),
			      mode, flags);
}

#ifdef __GLIBC__
int faccessat2(int dirfd, const char *path, int mode, int flags)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_faccessat2(dirfd, xlate_follow(buf, sizeof(buf), path),
			       mode, flags);
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

int chmod(const char *path, mode_t mode)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_chmod(xlate_follow(buf, sizeof(buf), path), mode);
}

int fchmodat(int dirfd, const char *path, mode_t mode, int flags)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_fchmodat(dirfd, xlate_follow(buf, sizeof(buf), path),
			     mode, flags);
}

int chown(const char *path, uid_t owner, gid_t group)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_chown(xlate_follow(buf, sizeof(buf), path), owner, group);
}

int lchown(const char *path, uid_t owner, gid_t group)
{
	char buf[PATH_MAX];

	init_real_all_once();
	return real_lchown(xlate(buf, sizeof(buf), path), owner, group);
}

int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags)
{
	char buf[PATH_MAX];

	init_real_all_once();
	if (flags & AT_SYMLINK_NOFOLLOW)
		return real_fchownat(dirfd, xlate(buf, sizeof(buf), path),
				     owner, group, flags);
	return real_fchownat(dirfd, xlate_follow(buf, sizeof(buf), path),
			     owner, group, flags);
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

	init_real_all_once();
	return real_dlopen(xlate(buf, sizeof(buf), filename), flags);
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
		size_t rest = strlen(res) - g_root_len;	/* keep the '/' */
		memmove(res, res + g_root_len, rest + 1);
	}
	return res;
}

/* ------------------------------------------------------------------ */
/* execve: resolve shebang + PT_INTERP + guest symlinks, then reroute  */
/* through the guest loader so chained execs stay translated           */
/* ------------------------------------------------------------------ */

/* Does the host-side ELF file request a dynamic loader (PT_INTERP)?  */
static int elf_uses_dyn_loader(const char *host_path, int *is_elf)
{
	unsigned char ehdr[64];
	unsigned char ph[56];
	uint64_t phoff;
	uint16_t phentsize, phnum;
	int fd, i, found;

	*is_elf = 0;
	fd = real_open(host_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;	/* propagate the error via execve */
	if (pread(fd, ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
		close(fd);
		return 0;	/* not an ELF (scripts handled elsewhere) */
	}
	if (memcmp(ehdr, "\x7f""ELF", 4) != 0) {
		close(fd);
		return 0;
	}
	*is_elf = (ehdr[4] == 2);	/* ELFCLASS64 only in the prototype */
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
		if (ptype == 3)	/* PT_INTERP */
			found = 1;
	}
	close(fd);
	return found;
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
	saved = errno;		/* execve failed; report through */
	free(navv);
	errno = saved;
	return -1;
}

static int do_execve(const char *path, char *const argv[], char *const envp[])
{
	static __thread char *nargv[4096];
	static __thread char pbuf[PATH_MAX];
	const char *prog;
	char interp[PATH_MAX], iarg[64];
	char *const *rest = (char *const *)argv;
	int is_elf, dyn;
	int depth;

	if (g_loader == NULL) {
		char buf[PATH_MAX];
		return real_execve(xlate_follow(buf, sizeof(buf), path),
				   argv, envp);
	}

	prog = xlate(pbuf, sizeof(pbuf), path);
	if (prog == NULL || prog[0] != '/')
		return real_execve(path, argv, envp);

	/* resolve guest symlinks first: applet/loader links carry
	 * guest-absolute targets the host kernel cannot follow */
	resolve_guest_links(pbuf, sizeof(pbuf));
	prog = pbuf;

	for (depth = 0; depth < 4; depth++) {
		int rc = resolve_shebang(prog, interp, sizeof(interp),
					 iarg, sizeof(iarg));
		if (rc < 0)
			return real_execve(prog, rest, envp);	/* ENOENT etc */
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

			snprintf(pbuf, sizeof(pbuf), "%s%s",
				 interp[0] == '/' ? g_root : "", interp);
			resolve_guest_links(pbuf, sizeof(pbuf));
			prog = pbuf;
		}
	}
not_script:
	dyn = elf_uses_dyn_loader(prog, &is_elf);
	if (is_elf && dyn)
		return exec_loader_route(prog, rest, envp);
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
