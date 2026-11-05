/* SPDX-License-Identifier: GPL-3.0-or-later */
/**
 * env_sanitize.c - keep the host environment from leaking into the
 * guest.
 *
 * A guest inherits the whole environment of the Termux shell that
 * started nproot.  That inheritance is harmless for TERM or LANG,
 * but four groups of variables actively break the guest or defeat
 * its isolation:
 *
 *   PATH      The Termux PATH points at bionic binaries.  They stay
 *             reachable from inside the guest (proot-distro binds
 *             /data/data/com.termux into the container), so a
 *             command like "apt" typed in an Alpine guest picks the
 *             host's bionic apt: the musl loader then fails its
 *             relocations against Termux libraries ("missing
 *             __errno", "__sF", ...).  Hand the guest a
 *             distro-standard PATH instead, exactly like a container
 *             runtime would; a login shell rebuilds it anyway.
 *
 *   TMPDIR    Termux exports TMPDIR under its prefix; guest programs
 *             would write temporary files into the host prefix (and
 *             into the reach of the host's own tmp cleaning).  The
 *             guest has its own /tmp.
 *
 *   LD_PRELOAD / LD_LIBRARY_PATH
 *             Both would push host (bionic) shared objects into the
 *             guest's loader.  The proto backend overwrites them
 *             right afterwards with the shim and the guest library
 *             dirs; the ptrace backend just drops the host values
 *             and leaves the guest loader to its built-in search.
 *
 * On top of that, glibc >= 2.35 registers restartable sequences
 * (rseq(2)) while initializing, before main().  The app seccomp
 * filter Android installs in Termux answers rseq(2) with
 * SECCOMP_RET_TRAP, so every dynamically linked glibc guest (Debian,
 * Ubuntu) died with SIGSYS ("Unknown signal 31") on affected
 * devices, while musl guests (Alpine) never issue the syscall.  Ask
 * glibc to skip the probe altogether (GLIBC_TUNABLES); the SIGSYS ->
 * ENOSYS guard the shim installs is the second line of defense,
 * covering clone3(2), faccessat2(2), close_range(2) and any other
 * trapped probe.  musl ignores the variable.
 *
 * NPROOT_KEEP_ENV=1 disables everything, for the users who
 * deliberately want the host environment inside the container.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "env_sanitize.h"

/* A distro-standard PATH, what a container runtime would set. */
#define GUEST_DEFAULT_PATH \
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/* The Termux prefix: every entry under it resolves to a bionic
 * binary or library of the host, never to something of the guest. */
#define TERMUX_PREFIX "/data/data/com.termux"

/**
 * Is the colon-separated entry @entry (of length @len) inside
 * @prefix?
 */
static bool entry_under_prefix(const char *entry, size_t len,
                               const char *prefix)
{
        size_t n = strlen(prefix);

        if (len < n)
                return false;
        if (strncmp(entry, prefix, n) != 0)
                return false;
        return len == n || entry[n] == '/';
}

/**
 * Drop every colon-separated entry of the variable @name that lives
 * under @prefix; unset the variable when nothing survives.
 */
static void drop_entries_under(const char *name, const char *prefix)
{
        const char *value = getenv(name);
        const char *cursor;
        char *kept, *write;

        if (value == NULL || strstr(value, prefix) == NULL)
                return;

        kept = malloc(strlen(value) + 1);
        if (kept == NULL)
                return; /* keep the original rather than half of it */
        write = kept;
        cursor = value;
        while (*cursor != '\0') {
                size_t len = strcspn(cursor, ":");
                const char *end = cursor + len;

                if (!entry_under_prefix(cursor, len, prefix)) {
                        if (write != kept)
                                *write++ = ':';
                        memcpy(write, cursor, len);
                        write += len;
                }
                cursor = (*end == ':') ? end + 1 : end;
        }
        *write = '\0';

        if (kept[0] == '\0')
                unsetenv(name);
        else
                setenv(name, kept, 1);
        free(kept);
}

void sanitize_guest_environment(bool separate_rootfs)
{
        const char *cur;

        /* Without a rootfs of its own the host IS the guest: nothing
         * to isolate, and stripping the host PATH would break the
         * very commands this session is meant to run.  */
        if (!separate_rootfs)
                return;

        /* Escape hatch: keep the inherited environment verbatim. */
        if (getenv("NPROOT_KEEP_ENV") != NULL)
                return;

        /* 1. PATH: see the module comment.  This also covers
         *     ~/bin and ~/.local/bin, which live under the Termux
         *     prefix too.  */
        setenv("PATH", GUEST_DEFAULT_PATH, 1);

        /* 2. TMPDIR pointing into the host prefix.  */
        cur = getenv("TMPDIR");
        if (cur != NULL &&
            entry_under_prefix(cur, strlen(cur), TERMUX_PREFIX))
                unsetenv("TMPDIR");

        /* 3./4. host library/preload entries.  */
        drop_entries_under("LD_LIBRARY_PATH", TERMUX_PREFIX);
        drop_entries_under("LD_PRELOAD", TERMUX_PREFIX);

        /* 5. the glibc rseq probe under the Android seccomp filter;
         *     see the module comment.  */
        cur = getenv("GLIBC_TUNABLES");
        if (cur == NULL || cur[0] == '\0')
                setenv("GLIBC_TUNABLES", "glibc.pthread.rseq=0", 1);
        else if (strstr(cur, "glibc.pthread.rseq") == NULL) {
                char buf[1024];

                snprintf(buf, sizeof(buf), "%s:glibc.pthread.rseq=0",
                         cur);
                setenv("GLIBC_TUNABLES", buf, 1);
        }
}
