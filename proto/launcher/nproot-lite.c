/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * nproot-lite.c - launcher for the LD_PRELOAD prototype (route D).
 *
 * Instead of ptrace(2), the guest is started through its own dynamic
 * loader with the nproot shim preloaded:
 *
 *   NPROOT_ROOT=<rootfs> NPROOT_LOADER=<guest ld.so> \
 *   LD_PRELOAD=libnproot.so LD_LIBRARY_PATH=<guest lib dirs> \
 *   exec <guest ld.so> -- <rootfs>/bin/prog args...
 *
 * Usage:
 *
 *   nproot-lite -r <rootfs> [-w <dir>] [-L <libnproot.so>] \
 *               [-l <guest ld.so>] -- program [args...]
 *
 *   -r  guest rootfs directory on the host (required)
 *   -w  initial working directory inside the guest (default: /)
 *   -L  path of libnproot.so (default: next to this binary)
 *   -l  guest dynamic loader (default: auto-detect by architecture)
 *
 * The shim must be built against the same libc family as the guest
 * (glibc guests on a glibc host: the default build; musl guests need
 * `make libnproot-musl.so` with musl-gcc installed).
 */
#define _GNU_SOURCE
#include <libgen.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

static char g_mach[64];

static const char *loader_candidates_x86_64[] = {
	"/lib64/ld-linux-x86-64.so.2",
	"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
	"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
	"/lib/ld-linux-x86-64.so.2",
	"/lib/ld-musl-x86_64.so.1",
	NULL,
};

static const char *loader_candidates_aarch64[] = {
	"/lib/ld-linux-aarch64.so.1",
	"/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
	"/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
	"/lib/ld-musl-aarch64.so.1",
	NULL,
};

static const char *libdirs_x86_64[] = {
	"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
	"/lib64", "/usr/lib64", "/lib", "/usr/lib", NULL,
};

static const char *libdirs_aarch64[] = {
	"/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
	"/lib64", "/usr/lib64", "/lib", "/usr/lib", NULL,
};

static int is_x86_64_host(void)
{
	return strncmp(g_mach, "x86_64", 6) == 0;
}

static const char *g_rootfs = "";

/* Resolve a guest-side symlink chain on the host.  Applet/loader
 * symlinks inside a rootfs carry guest-absolute targets that the
 * host kernel would resolve against the HOST root -- re-point them
 * into the rootfs here. */
static void resolve_guest_path(char *buf, size_t sz)
{
	char target[PATH_MAX];
	int depth;

	for (depth = 0; depth < 8; depth++) {
		ssize_t r = readlink(buf, target, sizeof(target) - 1);
		char dir[PATH_MAX], *slash;
		if (r < 0)
			return;	/* not a symlink (or error): done */
		target[r] = '\0';
		if (target[0] == '/') {
			snprintf(buf, sz, "%s%s", g_rootfs, target);
			continue;
		}
		snprintf(dir, sizeof(dir), "%s", buf);
		slash = strrchr(dir, '/');
		if (slash == NULL)
			return;
		*slash = '\0';
		snprintf(buf, sz, "%s/%s", dir, target);
	}
}

static int file_ok(const char *root, const char *rel)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s%s", root, rel);
	return access(path, R_OK | X_OK) == 0;
}

static const char *find_loader(const char *root)
{
	const char **cands = is_x86_64_host() ? loader_candidates_x86_64
					      : loader_candidates_aarch64;
	int i;

	for (i = 0; cands[i] != NULL; i++)
		if (file_ok(root, cands[i]))
			return cands[i];
	return NULL;
}

static void set_libdirs(const char *root)
{
	const char **dirs = is_x86_64_host() ? libdirs_x86_64
					     : libdirs_aarch64;
	char lpath[PATH_MAX * 4];
	size_t len = 0;
	int i;

	lpath[0] = '\0';
	for (i = 0; dirs[i] != NULL; i++) {
		char p[PATH_MAX];
		int n = snprintf(p, sizeof(p), "%s%s", root, dirs[i]);
		if (n < 0 || (size_t)n >= sizeof(p))
			continue;
		if (access(p, R_OK) != 0)
			continue;
		len += (size_t)snprintf(lpath + len, sizeof(lpath) - len,
					"%s%s", len ? ":" : "", p);
		if (len >= sizeof(lpath))
			break;
	}
	setenv("LD_LIBRARY_PATH", lpath, 1);
}

int main(int argc, char *argv[])
{
	const char *root = NULL, *wdir = "/", *lib = NULL, *loader = NULL;
	const char *prog;
	char rootr[PATH_MAX], progbuf[PATH_MAX], libbuf[PATH_MAX];
	char selfbin[PATH_MAX], selfdir[PATH_MAX], loaderbuf[PATH_MAX];
	struct utsname un;
	int i, argi;
	ssize_t k;
	const char *applet_arg = NULL;

	if (uname(&un) < 0) {
		perror("uname");
		return 1;
	}
	snprintf(g_mach, sizeof(g_mach), "%s", un.machine);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			i++;
			break;
		}
		if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
			root = argv[++i];
		} else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
			wdir = argv[++i];
		} else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) {
			lib = argv[++i];
		} else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
			loader = argv[++i];
		} else if (strncmp(argv[i], "-", 1) == 0) {
			fprintf(stderr, "nproot-lite: unknown option %s\n", argv[i]);
			return 2;
		} else {
			break;
		}
	}
	argi = i;

	if (root == NULL || argi >= argc) {
		fprintf(stderr,
			"usage: nproot-lite -r <rootfs> [-w <dir>] [-L <lib>] "
			"[-l <ld.so>] -- program [args...]\n");
		return 2;
	}

	if (realpath(root, rootr) == NULL) {
		fprintf(stderr, "nproot-lite: rootfs %s: %s\n", root, strerror(errno));
		return 1;
	}
	root = rootr;
	g_rootfs = root;

	/* locate libnproot.so next to this binary unless overridden */
	if (lib == NULL) {
		k = readlink("/proc/self/exe", selfbin, sizeof(selfbin) - 1);
		if (k < 0) {
			perror("readlink(/proc/self/exe)");
			return 1;
		}
		selfbin[k] = '\0';
		snprintf(selfdir, sizeof(selfdir), "%s", dirname(selfbin));
		snprintf(libbuf, sizeof(libbuf), "%s/../preload/libnproot.so", selfdir);
		lib = libbuf;
	}

	if (loader == NULL) {
		const char *rel = find_loader(root);
		if (rel == NULL) {
			fprintf(stderr,
				"nproot-lite: no dynamic loader found in %s; "
				"is this a rootfs with a libc?\n", root);
			return 1;
		}
		snprintf(loaderbuf, sizeof(loaderbuf), "%s%s", root, rel);
		loader = loaderbuf;
	} else if (loader[0] == '/' && access(loader, R_OK | X_OK) != 0) {
		/* given as a path inside the guest rootfs */
		char p[PATH_MAX];
		snprintf(p, sizeof(p), "%s%s", root, loader);
		snprintf(loaderbuf, sizeof(loaderbuf), "%s", p);
		loader = loaderbuf;
	} else {
		snprintf(loaderbuf, sizeof(loaderbuf), "%s", loader);
		loader = loaderbuf;
	}
	if (access(lib, R_OK) != 0) {
		fprintf(stderr, "nproot-lite: shim %s not found (build it with make)\n",
			lib);
		return 1;
	}
	/* The shim must match the guest libc family: if the guest loader
	 * is musl and a musl-built shim is available, prefer it.  */
	if (strstr(loader, "musl") != NULL) {
		char musllib[PATH_MAX];
		snprintf(musllib, sizeof(musllib), "%s/../preload/libnproot-musl.so",
			 selfdir);
		if (access(musllib, R_OK) == 0)
			lib = strdup(musllib);
	}


	resolve_guest_path(loaderbuf, sizeof(loaderbuf));

	if (strstr(loader, "musl") != NULL && strstr(lib, "musl") == NULL)
		fprintf(stderr,
			"nproot-lite: warning: musl guest but glibc shim; "
			"build preload/libnproot-musl.so\n");

	/* resolve the program inside the rootfs */
	prog = argv[argi];
	if (prog[0] == '/') {
		snprintf(progbuf, sizeof(progbuf), "%s%s", root, prog);
	} else {
		static const char *bindirs[] =
			{ "/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", NULL };
		int found = 0;
		for (i = 0; bindirs[i] != NULL; i++) {
			snprintf(progbuf, sizeof(progbuf), "%s%s%s",
				 root, bindirs[i], prog);
			if (access(progbuf, X_OK) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			fprintf(stderr, "nproot-lite: %s: not found in rootfs\n", prog);
			return 127;
		}
	}

	resolve_guest_path(progbuf, sizeof(progbuf));

	/* busybox applet dispatch: when the symlink chain landed on
	 * busybox, the requested applet (basename of the original
	 * guest path) must become busybox's first argument */
	{
		const char *pb = strrchr(progbuf, '/');
		const char *ob = strrchr(prog, '/');
		pb = pb ? pb + 1 : progbuf;
		ob = ob ? ob + 1 : prog;
		if (strcmp(pb, "busybox") == 0 && strcmp(ob, "busybox") != 0)
			applet_arg = ob;
	}

	setenv("NPROOT_ROOT", root, 1);
	setenv("NPROOT_LOADER", loader, 1);
	setenv("LD_PRELOAD", lib, 1);
	set_libdirs(root);

	if (wdir[0] != '\0' && strcmp(wdir, "/") != 0) {
		char wd[PATH_MAX];
		snprintf(wd, sizeof(wd), "%s%s", root, wdir);
		if (chdir(wd) < 0) {
			fprintf(stderr, "nproot-lite: chdir %s: %s\n", wd, strerror(errno));
			return 1;
		}
	} else if (chdir(root) < 0) {
		perror("chdir(root)");
		return 1;
	}

	{
		char *nargv[argc - argi + 5];
		int n = 0;

		nargv[n++] = loaderbuf;
		/* no "--" separator: glibc's ld.so (<= 2.36) does not know
		 * it, and musl's does not need it; progbuf is absolute so
		 * it can never be mistaken for an option */
		nargv[n++] = progbuf;
		if (applet_arg != NULL)
			nargv[n++] = (char *)applet_arg;
		for (i = argi + 1; i < argc; i++)
			nargv[n++] = argv[i];
		nargv[n] = NULL;

		if (getenv("NPROOT_DEBUG") != NULL)
			fprintf(stderr, "[nproot-lite] exec %s -- %s (LD_PRELOAD=%s)\n",
				loaderbuf, progbuf, lib);
		execv(loaderbuf, nargv);
		fprintf(stderr, "nproot-lite: exec %s: %s\n", loaderbuf, strerror(errno));
		return 127;
	}
}
