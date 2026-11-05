/* SPDX-License-Identifier: GPL-3.0-or-later */
/**
 * proto_launch.c - the LD_PRELOAD (no-ptrace) backend of nproot,
 * phase 1 of docs/BACKENDS.md.
 *
 * Instead of supervising the guest with ptrace(2), the guest is
 * started through its own dynamic loader with the nproot shim
 * (proto/preload/nproot_preload.c) preloaded:
 *
 *   NPROOT_ROOT=<rootfs> NPROOT_LOADER=<guest ld.so>            \
 *   NPROOT_BINDS=<host:guest;...> NPROOT_FAKEID0=1 (when -0)     \
 *   LD_PRELOAD=<shim> LD_LIBRARY_PATH=<guest lib dirs>           \
 *   exec <guest ld.so> [--argv0 <argv0>] <rootfs>/<prog> args...
 *
 * The shim then performs the path translation inside every guest
 * process, so the whole session runs with zero ptrace stoppages.
 * When this backend cannot carry the requested configuration (see
 * proto_infeasible_reason()), the caller falls back to the classic
 * ptrace backend.
 *
 * Shim lookup order: $NPROOT_SHIM, then <nproot dir>/preload/,
 * then the shims embedded into this binary at build time (make
 * EMBED_SHIM=1), extracted into the temporary directory on demand.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <elf.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "attribute.h"
#include "cli/note.h"
#include "env_sanitize.h"
#include "extension/extension.h"
#include "extension/fake_id0/config.h"
#include "path/binding.h"
#include "path/temp.h"
#include "proto/proto_launch.h"
#include "fileat.h"
#include "tracee/tracee.h"

static char g_mach[64];
static char g_family[8] = "unknown";

/**
 * The libc family of the guest loader, as probed by the last
 * proto_infeasible_reason() run: "musl", "glibc" or "unknown".  The
 * startup banner reports it next to the backend name.
 */
const char *proto_guest_libc(void)
{
        return g_family;
}

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

static const char **loader_candidates(void)
{
        return (strcmp(g_mach, "x86_64") == 0) ? loader_candidates_x86_64
                                               : loader_candidates_aarch64;
}

static const char **guest_libdirs(void)
{
        return (strcmp(g_mach, "x86_64") == 0) ? libdirs_x86_64
                                               : libdirs_aarch64;
}

static bool supported_machine(void)
{
        return strcmp(g_mach, "x86_64") == 0 || strcmp(g_mach, "aarch64") == 0;
}

/* The Android app runtime (zygote) installs a seccomp filter whose
 * default action for syscalls outside bionic's set is SECCOMP_RET_TRAP
 * -- SIGSYS, "Unknown signal 31".  Detect the Android host by files
 * only Android systems ship (the bionic system linker and the build
 * fingerprint).  */
static bool android_host(void)
{
        return access("/system/bin/linker64", F_OK) == 0 ||
               access("/system/build.prop", F_OK) == 0;
}

/* Whether the Android seccomp compatibility patches (patched loader
 * and libc copies, see make_seccomp_compat_copies()) apply: forced on
 * with NPROOT_SECCOMP_COMPAT=1 (tests), forced off with =0, and
 * auto-detected from the host otherwise.  */
static bool seccomp_compat_enabled(void)
{
        const char *env = getenv("NPROOT_SECCOMP_COMPAT");

        if (env != NULL)
                return strcmp(env, "0") != 0;
        return android_host();
}

/*---------------------------------------------------------------------
 * Android seccomp compatibility: patch set_robust_list out of the
 * guest's loader and libc copies.
 *
 * glibc >= 2.35 issues set_robust_list(2) from the dynamic loader's
 * own startup (and again from __libc_early_init in libc) -- before
 * preloads are relocated, before LD_AUDIT modules initialize, before
 * any constructor: no signal handler can be armed in time, SIG_IGN is
 * reset by force_sig(), and a seccomp filter we install cannot
 * override the app filter's SECCOMP_RET_TRAP (TRAP outranks
 * USER_NOTIF).  On an Android app filter that syscall is a killer.
 *
 * The registration is best-effort in every caller (the return value
 * is ignored, exactly like on pre-2.6.18 kernels), so the fix is to
 * exec a copy of the guest loader, and to put a copy of the guest
 * libc first on LD_LIBRARY_PATH, with the set_robust_list syscall
 * instruction itself nop'ed out.  The guest rootfs stays untouched;
 * the copies live in the session's temporary directory.  rseq(2),
 * the other pre-constructor probe, is suppressed by the launcher's
 * GLIBC_TUNABLES=glibc.pthread.rseq=0 AND nop'ed out of the libc copy
 * (belt and suspenders: the registration window sits inside
 * pthread_create's all-signals-blocked section, where no handler can
 * rescue a trap); clone3 and the post-constructor probes are covered
 * by the shim's SIGSYS handler and clone3 patch.
 *---------------------------------------------------------------------
 */

static const unsigned char srl_mov_x86_64[]   = { 0xB8, 0x11, 0x01, 0x00, 0x00 };
static const unsigned char srl_sysc_x86_64[] = { 0x0F, 0x05 };
static const unsigned char srl_nop_x86_64[]  = { 0x90, 0x90 };
static const unsigned char srl_mov_aarch64[]   = { 0x68, 0x0C, 0x80, 0xD2 };
static const unsigned char srl_sysc_aarch64[] = { 0x01, 0x00, 0x00, 0xD4 };
static const unsigned char srl_nop_aarch64[]  = { 0x1F, 0x20, 0x03, 0xD5 };

/* rseq(2): glibc registers it from __libc_early_init (before any
 * constructor, unreachable by the shim's guard) and again per thread
 * from inside pthread_create's all-signals-blocked window (a trapped
 * SIGSYS there is force_sig()ed to default).  GLIBC_TUNABLES normally
 * suppresses it; the nop is the belt to that suspenders.  The
 * registration treats any nonzero return as "unavailable", and x0/eax
 * still holds the nonzero TLS/struct address after the nop'ed-out
 * syscall, so leaving the register move in place is safe. */
static const unsigned char rseq_mov_x86_64[]   = { 0xB8, 0x4E, 0x01, 0x00, 0x00 };
static const unsigned char rseq_mov_aarch64[]  = { 0xA8, 0x24, 0x80, 0xD2 };

struct srl_pattern {
        const unsigned char *mov;      /* load syscall nr into the nr reg */
        size_t mov_len;
        const unsigned char *sysc;     /* the syscall instruction */
        size_t sysc_len;
        const unsigned char *nop;      /* same length as @sysc */
        size_t nop_len;
        bool word_aligned;             /* fixed 4-byte instructions */
        /* Optional: rewrite the nr-load itself (same length as @mov)
         * so the site returns -ENOSYS instead of leaving a positive
         * register value behind -- needed where callers check the
         * return (access(2) "succeeded" would be a lie). */
        const unsigned char *rep_mov;
        size_t rep_mov_len;
};

/* x86_64: set_robust_list = 273 (0x111), rseq = 334 (0x14e).
 * aarch64: set_robust_list = 99, rseq = 293; both encoded as
 * "movz x8, #nr".  (Numbers from asm/unistd_64.h and the generic
 * arm64 table -- double-check against the headers, not memory.) */
/* The loader's own rseq registration sits in the same pre-constructor
 * window (both Debian and Ubuntu arm64 loaders carry the site) and is
 * gated on a kernel-capability probe that real kernels pass -- a qemu
 * -strace census never sees it issue.  Patch it in the loader copy
 * just like set_robust_list. */
/* access(2), x86_64: glibc's ld.so validates LD_PRELOAD paths with
 * the legacy access syscall (nr 21, TRAP-class on Android 15 x86_64)
 * in the pre-constructor window, where no handler can be armed -- the
 * AVD launcher died exactly there, inside execve of the patched
 * loader.  The nr load is REWRITTEN to -ENOSYS (not just the syscall
 * nop'ed): a spuriously "successful" access() would be worse than a
 * failure.  aarch64 has no legacy access (glibc uses faccessat, nr
 * 48, allowlisted), so the arm64 lists stay untouched. */
static const unsigned char acc_mov_x86_64[]  = { 0xB8, 0x15, 0x00, 0x00, 0x00 };
static const unsigned char acc_rep_x86_64[]  = { 0xB8, 0xDA, 0xFF, 0xFF, 0xFF };

static const struct srl_pattern danger_loader[] = {
        { srl_mov_x86_64, 5, srl_sysc_x86_64, 2, srl_nop_x86_64, 2, false,
          NULL, 0 },
        { rseq_mov_x86_64, 5, srl_sysc_x86_64, 2, srl_nop_x86_64, 2, false,
          NULL, 0 },
        { acc_mov_x86_64, 5, srl_sysc_x86_64, 2, srl_nop_x86_64, 2, false,
          acc_rep_x86_64, 5 },
        { srl_mov_aarch64, 4, srl_sysc_aarch64, 4, srl_nop_aarch64, 4, true,
          NULL, 0 },
        { rseq_mov_aarch64, 4, srl_sysc_aarch64, 4, srl_nop_aarch64, 4, true,
          NULL, 0 },
        { NULL, 0, NULL, 0, NULL, 0, false, NULL, 0 },
};
static const struct srl_pattern danger_loader_aarch64[] = {
        { srl_mov_aarch64, 4, srl_sysc_aarch64, 4, srl_nop_aarch64, 4, true,
          NULL, 0 },
        { rseq_mov_aarch64, 4, srl_sysc_aarch64, 4, srl_nop_aarch64, 4, true,
          NULL, 0 },
        { NULL, 0, NULL, 0, NULL, 0, false, NULL, 0 },
};
static const struct srl_pattern danger_libc[] = {
        { srl_mov_x86_64, 5, srl_sysc_x86_64, 2, srl_nop_x86_64, 2, false,
          NULL, 0 },
        { srl_mov_aarch64, 4, srl_sysc_aarch64, 4, srl_nop_aarch64, 4, true,
          NULL, 0 },
        { rseq_mov_x86_64, 5, srl_sysc_x86_64, 2, srl_nop_x86_64, 2, false,
          NULL, 0 },
        { rseq_mov_aarch64, 4, srl_sysc_aarch64, 4, srl_nop_aarch64, 4, true,
          NULL, 0 },
        { acc_mov_x86_64, 5, srl_sysc_x86_64, 2, srl_nop_x86_64, 2, false,
          acc_rep_x86_64, 5 },
        { NULL, 0, NULL, 0, NULL, 0, false, NULL, 0 },
};
static const struct srl_pattern danger_libc_aarch64[] = {
        { srl_mov_aarch64, 4, srl_sysc_aarch64, 4, srl_nop_aarch64, 4, true,
          NULL, 0 },
        { rseq_mov_aarch64, 4, srl_sysc_aarch64, 4, srl_nop_aarch64, 4, true,
          NULL, 0 },
        { NULL, 0, NULL, 0, NULL, 0, false, NULL, 0 },
};

static const struct srl_pattern *danger_list_for(const char *machine,
                                                 bool libc)
{
        if (strcmp(machine, "x86_64") == 0)
                return libc ? danger_libc : danger_loader;
        if (strcmp(machine, "aarch64") == 0)
                return libc ? danger_libc_aarch64 : danger_loader_aarch64;
        return NULL;
}

/* Would the bytes between a "mov nr" and its "syscall" make the pair
 * unsafe to patch?  Only register shuffling may sit in between: no
 * other syscall, no branch, no second syscall-number load. */
static bool srl_gap_is_safe(const struct srl_pattern *p,
                            const unsigned char *gap, size_t len)
{
        size_t i;

        if (p->word_aligned) {
                for (i = 0; i + p->sysc_len <= len; i += 4) {
                        unsigned int word = 0;
                        size_t j;

                        for (j = 0; j < 4; j++)
                                word = (word << 8) | gap[i + j];
                        /* conditional/unconditional branches, bl/bra,
                         * cbz/cbnz/tbz/tbnz, ret, and svc itself */
                        switch (word >> 24) {
                        case 0x14: case 0x17: case 0x54:
                        case 0x94: case 0x97: case 0xD6:
                                return false;
                        }
                        if (word == 0xD4000001u)
                                return false;
                }
                return true;
        }

        for (i = 0; i + 1 < len; i++) {
                if (gap[i] == 0x0F && gap[i + 1] == 0x05)
                        return false;       /* another syscall */
                if (gap[i] == 0xB8)
                        return false;       /* another mov eax, imm */
        }
        for (i = 0; i < len; i++) {
                if (gap[i] == 0xE8 || gap[i] == 0xE9 || gap[i] == 0xEB ||
                    gap[i] == 0xC3 || gap[i] == 0xC2 || gap[i] == 0xFF)
                        return false;       /* call/jmp/ret/indirect */
        }
        return true;
}

static int patch_danger_syscalls(unsigned char *buf, size_t size,
                                 const char *machine, bool libc);
static int patch_one_pattern(unsigned char *buf, size_t size,
                             const struct srl_pattern *p);

/* Patch every "load nr; ... ; syscall" pair inside [buf, buf+size)
 * that lives in an executable PT_LOAD segment, for each entry of the
 * danger list selected by @libc (loader: set_robust_list; libc:
 * set_robust_list + rseq).  Returns the number of syscalls nop'ed
 * out.  Only bytes inside PF_X segments are touched, so data blobs
 * that happen to match do not corrupt the file. */
static int patch_danger_syscalls(unsigned char *buf, size_t size,
                                 const char *machine, bool libc)
{
        const struct srl_pattern *list = danger_list_for(machine, libc);
        int count = 0, k;

        if (list == NULL || size < 64)
                return 0;
        for (k = 0; list[k].mov != NULL; k++)
                count += patch_one_pattern(buf, size, &list[k]);
        return count;
}

static int patch_one_pattern(unsigned char *buf, size_t size,
                             const struct srl_pattern *p)
{
        unsigned char e_ident[16];
        size_t phoff;
        int phentsize, phnum, count = 0, i;

        if (size < 64)
                return 0;
        memcpy(e_ident, buf, 16);
        if (memcmp(e_ident, ELFMAG, 4) != 0 || e_ident[EI_CLASS] != ELFCLASS64)
                return 0;
        phoff = (size_t)((Elf64_Ehdr *)buf)->e_phoff;
        phentsize = (int)((Elf64_Ehdr *)buf)->e_phentsize;
        phnum = (int)((Elf64_Ehdr *)buf)->e_phnum;
        if (phoff == 0 || phentsize < (int)sizeof(Elf64_Phdr) ||
            phnum <= 0 || phoff + (size_t)phnum * phentsize > size)
                return 0;

        for (i = 0; i < phnum; i++) {
                Elf64_Phdr *ph = (Elf64_Phdr *)(buf + phoff + i * phentsize);
                const unsigned char *seg, *end, *q;
                size_t step = p->word_aligned ? 4 : 1;

                if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X))
                        continue;
                if (ph->p_filesz < p->mov_len ||
                    ph->p_offset >= size ||
                    ph->p_offset + ph->p_filesz > size)
                        continue;
                seg = buf + (size_t)ph->p_offset;
                end = seg + ph->p_filesz - p->mov_len;

                for (q = seg; q <= end; q += step) {
                        const unsigned char *sysc;
                        size_t lookahead = 32;

                        if (memcmp(q, p->mov, p->mov_len) != 0)
                                continue;
                        sysc = q + p->mov_len;
                        while (sysc + p->sysc_len <= q + p->mov_len + lookahead) {
                                if (memcmp(sysc, p->sysc, p->sysc_len) == 0)
                                        break;
                                sysc += step;
                        }
                        if (sysc + p->sysc_len > q + p->mov_len + lookahead ||
                            sysc + p->sysc_len > buf + size)
                                continue;
                        if (!srl_gap_is_safe(p, q + p->mov_len,
                                             (size_t)(sysc - (q + p->mov_len))))
                                continue;
                        memcpy((unsigned char *)sysc, p->nop, p->nop_len);
                        if (p->rep_mov != NULL)
                                memcpy((unsigned char *)q, p->rep_mov,
                                       p->rep_mov_len);
                        count++;
                }
        }
        return count;
}

/* Read @src, patch its danger-list syscalls (set_robust_list, and
 * rseq for libc copies) out, and write the result to "<tmp>/<name>"
 * (mode @mode).  Returns the talloc'ed path of the patched copy, or
 * NULL when nothing had to be patched.  *count receives the number of
 * patched syscall sites, or -1 when the file could not be read or
 * written (a real failure worth a warning). */
static char *make_patched_copy(const Tracee *tracee, const char *src,
                               const char *name, mode_t mode, int *count,
                               bool libc_file)
{
        char path[PATH_MAX];
        unsigned char *buf;
        FILE *fp;
        long fsize;
        size_t got;
        int fd, i;

        *count = -1;
        fp = fopen(src, "rb");
        if (fp == NULL) {
                note(tracee, WARNING, SYSTEM, "无法读取 '%s'", src);
                return NULL;
        }
        if (fseek(fp, 0, SEEK_END) != 0 || (fsize = ftell(fp)) < 0 ||
            fseek(fp, 0, SEEK_SET) != 0 || fsize > 32L * 1024 * 1024) {
                note(tracee, WARNING, INTERNAL, "无法确定 '%s' 的大小", src);
                fclose(fp);
                return NULL;
        }
        buf = malloc(fsize > 0 ? (size_t)fsize : 1);
        if (buf == NULL) {
                fclose(fp);
                return NULL;
        }
        got = fread(buf, 1, (size_t)fsize, fp);
        fclose(fp);
        if (got != (size_t)fsize) {
                note(tracee, WARNING, SYSTEM, "读取 '%s' 不完整", src);
                free(buf);
                return NULL;
        }

        *count = patch_danger_syscalls(buf, got, g_mach, libc_file);
        if (*count == 0) {
                free(buf);
                return NULL;
        }

        for (i = 0; i < 2; i++) {
                snprintf(path, sizeof(path), "%s/%s", get_temp_directory(),
                         name);
                fd = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
                if (fd >= 0)
                        break;
                if (errno == EEXIST) {
                        unlink(path);
                        continue;
                }
        }
        if (fd < 0) {
                note(tracee, WARNING, SYSTEM,
                     "无法在 '%s' 创建 seccomp 兼容副本", get_temp_directory());
                free(buf);
                *count = -1;
                return NULL;
        }
        got = 0;
        while (got < (size_t)fsize) {
                ssize_t w = write(fd, buf + got, (size_t)fsize - got);

                if (w <= 0) {
                        if (errno == EINTR)
                                continue;
                        note(tracee, WARNING, SYSTEM, "写入 seccomp 兼容副本失败");
                        close(fd);
                        unlink(path);
                        free(buf);
                        *count = -1;
                        return NULL;
                }
                got += (size_t)w;
        }
        close(fd);
        free(buf);
        return talloc_strdup(talloc_autofree_context(), path);
}

/*---------------------------------------------------------------------
 * Shim availability: environment, next to the binary, or embedded.
 *---------------------------------------------------------------------
 */

/* Embedded blobs (objcopy), present only when built with EMBED_SHIM.
 * Weak: unresolved when the build carries no shim.  */
extern unsigned char WEAK _binary_shim_glibc_so_start;
extern unsigned char WEAK _binary_shim_glibc_so_end;
extern unsigned char WEAK _binary_shim_musl_so_start;
extern unsigned char WEAK _binary_shim_musl_so_end;

static const void *embedded_shim(bool wants_musl, size_t *size)
{
        if (wants_musl) {
                if (&_binary_shim_musl_so_start == NULL)
                        return NULL;
                *size = (size_t)(&_binary_shim_musl_so_end
                                 - &_binary_shim_musl_so_start);
                return &_binary_shim_musl_so_start;
        }
        if (&_binary_shim_glibc_so_start == NULL)
                return NULL;
        *size = (size_t)(&_binary_shim_glibc_so_end
                         - &_binary_shim_glibc_so_start);
        return &_binary_shim_glibc_so_start;
}

/**
 * Extract an embedded shim into the temporary directory.  Returns a
 * talloc'ed path or NULL (after reporting).
 */
static char *extract_shim(const Tracee *tracee, bool wants_musl)
{
        const void *start;
        size_t size, total;
        char path[PATH_MAX];
        int fd, i;

        start = embedded_shim(wants_musl, &size);
        if (start == NULL)
                return NULL;

        for (i = 0; i < 2; i++) {
                snprintf(path, sizeof(path), "%s/nproot-shim-%s-%d.so",
                         get_temp_directory(), wants_musl ? "musl" : "glibc",
                         (int)getpid());
                fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
                if (fd >= 0)
                        break;
                if (errno == EEXIST) {
                        unlink(path);
                        continue;
                }
                note(tracee, ERROR, SYSTEM, "无法在 '%s' 创建注入垫片",
                     get_temp_directory());
                return NULL;
        }
        if (fd < 0) {
                note(tracee, ERROR, SYSTEM, "无法在 '%s' 创建注入垫片",
                     get_temp_directory());
                return NULL;
        }

        total = 0;
        while (total < size) {
                ssize_t written = write(fd, (const char *)start + total,
                                        size - total);
                if (written <= 0) {
                        if (errno == EINTR)
                                continue;
                        note(tracee, ERROR, SYSTEM, "无法写入注入垫片");
                        close(fd);
                        unlink(path);
                        return NULL;
                }
                total += (size_t)written;
        }
        close(fd);

        if (access(path, R_OK) != 0) {
                note(tracee, ERROR, INTERNAL,
                     "解包出的注入垫片 '%s' 不可读（临时目录挂载了 noexec 或只读？）", path);
                unlink(path);
                return NULL;
        }

        return talloc_strdup(talloc_autofree_context(), path);
}

/**
 * Find a shim that matches the guest's libc family.  *wants_musl*
 * comes from the guest loader name.  Returns NULL when nothing
 * usable is around.
 */
static char *find_shim(const Tracee *tracee, bool wants_musl)
{
        const char *env;
        char selfbin[PATH_MAX], selfdir[PATH_MAX], buf[PATH_MAX];
        char *slash, *result;
        ssize_t len;

        /* 1. explicit override */
        env = getenv("NPROOT_SHIM");
        if (env != NULL && access(env, R_OK) == 0)
                return talloc_strdup(talloc_autofree_context(), env);

        /* 2. shipped next to this binary (artifact layout:
         *    <dir>/nproot + <dir>/preload/libnproot*.so)  */
        len = readlink("/proc/self/exe", selfbin, sizeof(selfbin) - 1);
        if (len > 0) {
                selfbin[len] = '\0';
                slash = strrchr(selfbin, '/');
                if (slash != NULL) {
                        slash[1] = '\0';
                        snprintf(selfdir, sizeof(selfdir), "%s", selfbin);

                        snprintf(buf, sizeof(buf),
                                 "%spreload/libnproot%s.so", selfdir,
                                 wants_musl ? "-musl" : "");
                        if (access(buf, R_OK) == 0)
                                return talloc_strdup(
                                        talloc_autofree_context(), buf);

                        /* development layout: proto/bin/<arch>/nproot-lite
                         * and proto/preload/ side by side */
                        snprintf(buf, sizeof(buf),
                                 "%s../preload/libnproot%s.so", selfdir,
                                 wants_musl ? "-musl" : "");
                        if (access(buf, R_OK) == 0)
                                return talloc_strdup(
                                        talloc_autofree_context(), buf);
                }
        }

        /* 3. embedded into this binary */
        result = extract_shim(tracee, wants_musl);
        if (result != NULL)
                return result;

        /* 4. a family-mismatched shim is worse than no shim: the guest
         * loader would reject it deep inside execve with a cryptic
         * message.  Report honestly instead.  */
        return NULL;
}

/*---------------------------------------------------------------------
 * Feasibility
 *---------------------------------------------------------------------
 */

const char *proto_infeasible_reason(const Tracee *tracee)
{
        struct utsname un;
        const char **candidates;
        char buf[PATH_MAX];
        const char *root;
        bool wants_musl;
        int i;

        if (tracee->qemu != NULL)
                return "-q/-Q 模拟器需要 ptrace 后端";

        if (uname(&un) < 0)
                return "uname(2) 调用失败";
        snprintf(g_mach, sizeof(g_mach), "%s", un.machine);
        if (!supported_machine())
                return "仅支持 64 位 x86_64/aarch64 容器";

        /* a non-zero fake identity has no shim-side emulation yet */
        if (get_extension((Tracee *)tracee, fake_id0_callback) != NULL) {
                Extension *ext = get_extension((Tracee *)tracee,
                                               fake_id0_callback);
                if (ext->config != NULL) {
                        Config *config =
                                talloc_get_type_abort(ext->config, Config);
                        if (config->ruid != 0 || config->euid != 0 ||
                            config->suid != 0 || config->rgid != 0 ||
                            config->egid != 0 || config->sgid != 0)
                                return "非零的 --change-id/-i 身份切换"
                                       "需要 ptrace 后端";
                }
        }

        /* the guest must have a dynamic loader to route through */
        root = get_root(tracee);
        if (root == NULL)
                return "未配置容器根文件系统";

        candidates = loader_candidates();
        for (i = 0; candidates[i] != NULL; i++) {
                snprintf(buf, sizeof(buf), "%s%s", root, candidates[i]);
                if (access(buf, R_OK | X_OK) == 0)
                        break;
        }
        if (candidates[i] == NULL)
                return "根文件系统中没有动态链接器（纯静态根文件系统？）";

        wants_musl = strstr(candidates[i], "musl") != NULL;
        snprintf(g_family, sizeof(g_family), "%s",
                 wants_musl ? "musl" : "glibc");

        /* A glibc guest on Android rides the seccomp compatibility
         * patches in proto_launch() (patched loader + libc copies),
         * not a backend switch: the whole point of nproot is to run
         * without ptrace, and the ptrace fallback stays for what it
         * was -- the guaranteed last resort for configurations proto
         * cannot carry at all.  */

        if (find_shim(tracee, wants_musl) == NULL)
                return wants_musl
                       ? "没有 musl 系的注入 shim 可用（设置 NPROOT_SHIM"
                         " 或附带 preload/libnproot-musl.so）"
                       : "没有可用的注入 shim（设置 NPROOT_SHIM 或附带"
                         " preload/libnproot.so）";

        return NULL;
}

/*---------------------------------------------------------------------
 * Launch
 *---------------------------------------------------------------------
 */

/**
 * Serialize the canonicalized binding list into NPROOT_BINDS format
 * ("host:guest;host:guest").  ptrace-internal pseudo-bindings (the
 * host-root glue and the /etc/ld.so.preload placeholder) are skipped.
 */
static void set_binds_env(const Tracee *tracee)
{
        char buf[16384];
        size_t len = 0;
        struct bindings *list;
        bool pending;
        Binding *binding;

        buf[0] = '\0';

        /* before launch_process() has canonicalized anything, the user
         * bindings live in the "pending" list (linked through
         * link.pending); afterwards they live in bindings.guest */
        pending = (tracee->fs->bindings.guest == NULL ||
                   CIRCLEQ_EMPTY(tracee->fs->bindings.guest));
        list = pending ? tracee->fs->bindings.pending
                       : tracee->fs->bindings.guest;

        if (list != NULL && !CIRCLEQ_EMPTY(list)) {
                binding = CIRCLEQ_FIRST(list);
                while ((void *)binding != (void *)list) {
                        const char *host = binding->host.path;
                        const char *guest = binding->guest.path;
                        char resolved[PATH_MAX];
                        int n;

                        /* ptrace machinery, meaningless for the shim */
                        if (strcmp(guest, HOST_ROOTFS) == 0 ||
                            strcmp(guest, "/etc/ld.so.preload") == 0)
                                goto next;

                        /* the rootfs itself is handled by the rootfs
                         * prefix; keep the bind table for the rest */
                        if (strcmp(guest, "/") == 0)
                                goto next;

                        /* canonicalized lists store absolute paths already;
                         * the pending list may carry relative hosts */
                        if (host[0] != '/') {
                                if (realpath(host, resolved) == NULL)
                                        goto next;
                                host = resolved;
                        }
                        if (guest[0] != '/')
                                goto next;

                        n = snprintf(buf + len, sizeof(buf) - len, "%s%s:%s",
                                     len > 0 ? ";" : "", host, guest);
                        if (n < 0 || (size_t)n >= sizeof(buf) - len)
                                break;  /* table full: keep what fits */
                        len += (size_t)n;
next:
                        binding = pending
                                  ? CIRCLEQ_NEXT(binding, link.pending)
                                  : CIRCLEQ_NEXT(binding, link.guest);
                }
        }

        setenv("NPROOT_BINDS", buf, 1);
        if (global_verbose_level >= 2)
                note(tracee, INFO, INTERNAL, "NPROOT_BINDS=%s", buf);
}

static bool file_exists_prefixed(const char *root, const char *rel)
{
        char path[PATH_MAX];

        snprintf(path, sizeof(path), "%s%s", root, rel);
        return access(path, R_OK) == 0;
}

/**
 * Resolve a guest path (symlink chains carry guest-absolute targets
 * the host kernel cannot follow).
 */
static void resolve_guest_path(char *buf, size_t sz, const char *root)
{
        char target[PATH_MAX];
        int depth;

        for (depth = 0; depth < 8; depth++) {
                char dir[PATH_MAX], *slash;
                ssize_t r = readlink(buf, target, sizeof(target) - 1);

                if (r < 0)
                        return; /* not a symlink (or error): done */
                target[r] = '\0';
                if (target[0] == '/') {
                        snprintf(buf, sz, "%s%s", root, target);
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

/* --kill-on-exit for the proto backend.  PRoot's ptrace backend kills
 * every tracee when the session ends; proto has no tracee list (the
 * launcher itself becomes the guest through execve), so instead this
 * process stays behind as a supervisor around the guest child:
 *
 *   - the child leads a fresh process group, so one killpg() reaches
 *     everything that did not deliberately change its group;
 *   - this process is a child subreaper, so orphaned grandchildren
 *     reparent here instead of escaping to init, and a /proc/ppid
 *     sweep catches the rest (setsid'ed daemons included);
 *   - terminal-oriented signals are forwarded to the guest group;
 *     the foreground is handed to the guest up front and taken back
 *     on the way out.
 *
 * Never returns: exits with the guest's status. */
static void proto_supervise(Tracee *tracee, pid_t guest)
{
        struct sigaction sa;
        sigset_t blockall;
        static const int forwarded[] = {
                SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP,
                SIGTTIN, SIGTTOU, SIGCONT, SIGUSR1, SIGUSR2,
        };
        bool foreground;
        int guest_status = 0, status, i;

        (void)tracee;

        prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

        foreground = isatty(0) && tcgetpgrp(0) == getpgrp();
        if (foreground)
                tcsetpgrp(0, guest);   /* best effort; ignore errors */

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        /* terminal writes from the background would stop us */
        sigaction(SIGTTOU, &sa, NULL);
        sigaction(SIGTTIN, &sa, NULL);

        sa.sa_handler = SIG_DFL;
        for (i = 0; i < (int)(sizeof(forwarded) / sizeof(forwarded[0])); i++)
                sigaction(forwarded[i], &sa, NULL);

        /* wait for the guest shell; EINTR just means a forwarded or
         * ignored signal interrupted us */
        while (waitpid(guest, &guest_status, 0) < 0 && errno == EINTR)
                ;

        /* the shell is gone: tear down whatever it left behind */
        sigfillset(&blockall);
        sigprocmask(SIG_BLOCK, &blockall, NULL);

        kill(-guest, SIGCONT);
        kill(-guest, SIGHUP);
        kill(guest, SIGCONT);
        kill(guest, SIGHUP);

        /* reap the direct orphaned children first (subreaper makes
         * them ours), then sweep any deeper descendants through
         * /proc before they can re-parent away. */
        while (waitpid(-1, &status, WNOHANG) > 0)
                ;
        for (i = 0; i < 3; i++) {
                DIR *dir;
                struct dirent *de;

                usleep(100000);
                dir = opendir("/proc");
                if (dir == NULL)
                        break;
                while ((de = readdir(dir)) != NULL) {
                        char path[64], buf[512];
                        int fd, n;
                        char *p;
                        pid_t pid, ppid;

                        if (de->d_name[0] < '0' || de->d_name[0] > '9')
                                continue;
                        pid = (pid_t)atoi(de->d_name);
                        if (pid <= 1 || pid == getpid())
                                continue;
                        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
                        fd = open(path, O_RDONLY);
                        if (fd < 0)
                                continue;
                        n = (int)read(fd, buf, sizeof(buf) - 1);
                        close(fd);
                        if (n <= 0)
                                continue;
                        buf[n] = '\0';
                        /* comm may contain spaces/parens: skip past the
                         * last ')' before the state field */
                        p = strrchr(buf, ')');
                        if (p == NULL)
                                continue;
                        /* "state ppid ..." */
                        ppid = (pid_t)strtol(p + 2 + 2, NULL, 10);
                        if (ppid == guest || ppid == getpid())
                                kill(pid, SIGKILL);
                }
                closedir(dir);
                while (waitpid(-1, &status, WNOHANG) > 0)
                        ;
        }
        kill(-guest, SIGKILL);

        if (foreground)
                tcsetpgrp(0, getpgrp());   /* give the terminal back */

        if (WIFEXITED(guest_status))
                _exit(WEXITSTATUS(guest_status));
        if (WIFSIGNALED(guest_status)) {
                /* a silent death through pd used to hide even the
                 * signal number; surface it */
                note(tracee, WARNING, USER, "容器主进程死于信号 %d（退出码 %d）",
                     WTERMSIG(guest_status), 128 + WTERMSIG(guest_status));
                _exit(128 + WTERMSIG(guest_status));
        }
        _exit(0);
}

void proto_launch(Tracee *tracee, char *const argv[])
{
        const char *root, *prog, *wdir;
        char rootr[PATH_MAX], progbuf[PATH_MAX], loaderbuf[PATH_MAX];
        char lpath[PATH_MAX * 4];
        char libcdir[PATH_MAX] = "";
        char *shim, **nargv;
        struct utsname un;
        const char **candidates, **libdirs;
        bool wants_musl, use_argv0, fake_id0;
        bool user_debug, user_census;
        const char *applet_arg = NULL;
        const char *loader_rel = NULL;
        int i, argi, nb_args, n;

        /* The environment sanitizer drops unknown variables, so a
         * user-provided NPROOT_DEBUG / NPROOT_CENSUS would never reach
         * the shim; record the wishes now and re-inject them after
         * sanitizing. */
        user_debug = getenv("NPROOT_DEBUG") != NULL;
        user_census = getenv("NPROOT_CENSUS") != NULL;

        if (uname(&un) < 0) {
                note(tracee, ERROR, SYSTEM, "uname()");
                goto fail;
        }
        snprintf(g_mach, sizeof(g_mach), "%s", un.machine);

        root = get_root(tracee);
        if (root == NULL) {
                note(tracee, ERROR, USER, "未配置容器根文件系统");
                goto fail;
        }
        if (realpath(root, rootr) == NULL) {
                note(tracee, ERROR, SYSTEM, "无法解析根文件系统路径 '%s'",
                     root);
                goto fail;
        }
        root = rootr;

        /* The proto session always runs against a rootfs of its own
         * (a session with the default root "/" never gets here:
         * proto_infeasible_reason() sent it to the ptrace backend
         * already).  Keep the host environment out of the guest
         * before anything of it is started.  */
        sanitize_guest_environment(true);

        /* locate the guest loader */
        candidates = loader_candidates();
        for (i = 0; candidates[i] != NULL; i++) {
                if (file_exists_prefixed(root, candidates[i])) {
                        loader_rel = candidates[i];
                        break;
                }
        }
        if (loader_rel == NULL) {
                note(tracee, ERROR, USER,
                     "在 '%s' 中找不到动态加载器；proto 后端需要带 libc 的根文件系统", root);
                goto fail;
        }
        snprintf(loaderbuf, sizeof(loaderbuf), "%s%s", root, loader_rel);
        resolve_guest_path(loaderbuf, sizeof(loaderbuf), root);
        wants_musl = strstr(loader_rel, "musl") != NULL;
        snprintf(g_family, sizeof(g_family), "%s",
                 wants_musl ? "musl" : "glibc");

        /* shim matching the guest libc family */
        shim = find_shim(tracee, wants_musl);
        if (shim == NULL) {
                note(tracee, ERROR, USER,
                     "没有可用的 %s 注入垫片（见 NPROOT_SHIM）",
                     wants_musl ? "musl" : "glibc");
                goto fail;
        }

        /* Android seccomp compatibility for glibc guests: run a copy
         * of the guest loader with set_robust_list nop'ed out, and put
         * a patched copy of the guest libc first on LD_LIBRARY_PATH.
         * Nothing runs before the loader's own set_robust_list probe
         * (verified: preload constructors, LD_AUDIT and ifunc
         * resolvers all come later), so patching the bytes we exec is
         * the only way to keep the guest alive under the app filter
         * while staying on the proto backend.  musl never issues the
         * syscall, and off-Android hosts keep the pristine files
         * (force with NPROOT_SECCOMP_COMPAT=1, e.g. for tests).  */
        if (!wants_musl && seccomp_compat_enabled()) {
                char name[64];
                char libcp[PATH_MAX];
                int npatch = 0;
                char *patched;

                /* name the family into the copy: the shim's exec
                 * reroute checks g_loader for "ld-linux" to decide
                 * whether --argv0 applies */
                snprintf(name, sizeof(name), "nproot-ld-linux-%d.so",
                         (int)getpid());
                patched = make_patched_copy(tracee, loaderbuf, name, 0755,
                                             &npatch, false);
                if (patched != NULL) {
                        snprintf(loaderbuf, sizeof(loaderbuf), "%s", patched);
                        note(tracee, INFO, USER,
                             "Android seccomp 兼容：已修补动态加载器副本"
                             "（禁用 set_robust_list ×%d，容器根文件系统不受影响）",
                             npatch);
                } else if (npatch < 0) {
                        note(tracee, WARNING, USER,
                             "无法修补动态加载器：glibc 容器在 Android 应用"
                             " seccomp 过滤下可能因信号 31 启动失败");
                } /* npatch == 0: the loader has no danger-list site at
                   * all (e.g. x86_64 glibc) -- nothing to do */

                /* the guest libc: same treatment, its own probe fires
                 * from __libc_early_init before any constructor */
                libcp[0] = '\0';
                libdirs = guest_libdirs();
                for (i = 0; libdirs[i] != NULL; i++) {
                        snprintf(libcp, sizeof(libcp), "%s%s/libc.so.6",
                                 root, libdirs[i]);
                        resolve_guest_path(libcp, sizeof(libcp), root);
                        if (access(libcp, R_OK) == 0)
                                break;
                        libcp[0] = '\0';
                }
                if (libcp[0] != '\0') {
                        snprintf(name, sizeof(name), "nproot-libc-%d/libc.so.6",
                                 (int)getpid());
                        {
                                char dirbuf[PATH_MAX];

                                snprintf(dirbuf, sizeof(dirbuf), "%s/nproot-libc-%d",
                                         get_temp_directory(), (int)getpid());
                                mkdir(dirbuf, 0755);
                        }
                        npatch = 0;
                        patched = make_patched_copy(tracee, libcp, name, 0755,
                                                     &npatch, true);
                        if (patched != NULL) {
                                snprintf(libcdir, sizeof(libcdir),
                                         "%s/nproot-libc-%d",
                                         get_temp_directory(), (int)getpid());
                                note(tracee, INFO, USER,
                                     "Android seccomp 兼容：已修补容器 libc 副本"
                                     "（禁用 set_robust_list/rseq ×%d，优先于容器原库加载）",
                                     npatch);
                        }
                } else {
                        note(tracee, WARNING, USER,
                             "未找到容器 libc（%s/libc.so.6），跳过其 seccomp 兼容修补",
                             libdirs[0] ? libdirs[0] : "");
                }
        }

        /* resolve the program inside the rootfs */
        prog = argv[0];
        if (prog == NULL) {
                note(tracee, ERROR, USER, "没有要运行的程序");
                goto fail;
        }
        if (prog[0] == '/') {
                snprintf(progbuf, sizeof(progbuf), "%s%s", root, prog);
        } else {
                static const char *bindirs[] = { "/bin/", "/usr/bin/",
                                                 "/sbin/", "/usr/sbin/", NULL };
                bool found = false;

                for (i = 0; bindirs[i] != NULL; i++) {
                        snprintf(progbuf, sizeof(progbuf), "%s%s%s", root,
                                 bindirs[i], prog);
                        if (access(progbuf, X_OK) == 0) {
                                found = true;
                                break;
                        }
                }
                if (!found) {
                        note(tracee, ERROR, USER,
                             "'%s'：在根文件系统中未找到", prog);
                        goto fail;
                }
        }
        resolve_guest_path(progbuf, sizeof(progbuf), root);

        /* busybox applet dispatch (see the shim's execve hook) */
        {
                const char *pb = strrchr(progbuf, '/');
                const char *ob = strrchr(prog, '/');

                pb = pb ? pb + 1 : progbuf;
                ob = ob ? ob + 1 : prog;
                if (strcmp(pb, "busybox") == 0 && strcmp(ob, "busybox") != 0)
                        applet_arg = ob;
        }

        /* environment for the shim */
        setenv("NPROOT_ROOT", root, 1);
        setenv("NPROOT_LOADER", loaderbuf, 1);
        set_binds_env(tracee);

        fake_id0 = false;
        {
                Extension *ext = get_extension(tracee, fake_id0_callback);

                if (ext != NULL && ext->config != NULL) {
                        Config *config =
                                talloc_get_type_abort(ext->config, Config);
                        if (config->ruid == 0 && config->euid == 0 &&
                            config->suid == 0 && config->rgid == 0 &&
                            config->egid == 0 && config->sgid == 0)
                                fake_id0 = true;
                }
        }
        if (fake_id0)
                setenv("NPROOT_FAKEID0", "1", 1);
        else
                unsetenv("NPROOT_FAKEID0");

        if (tracee->verbose >= 2 || user_debug)
                setenv("NPROOT_DEBUG", "1", 1);
        else
                unsetenv("NPROOT_DEBUG");

        /* Debug launches also arm the shim's one-shot seccomp census:
         * it forks ~900 disposable probes, so it stays off by default,
         * but its two summary lines are exactly what a device whose
         * filter deviates from the AOSP policies needs to show. */
        if (tracee->verbose >= 2 || user_census)
                setenv("NPROOT_CENSUS", "1", 1);

        setenv("LD_PRELOAD", shim, 1);

        /* guest library dirs for the guest loader itself; the patched
         * libc copy (Android seccomp compat) comes first so it wins
         * the SONAME lookup */
        libdirs = guest_libdirs();
        lpath[0] = '\0';
        n = 0;
        for (i = 0; libdirs[i] != NULL; i++) {
                char p[PATH_MAX];
                int m = snprintf(p, sizeof(p), "%s%s", root, libdirs[i]);

                if (m < 0 || (size_t)m >= sizeof(p))
                        continue;
                if (access(p, R_OK) != 0)
                        continue;
                m = snprintf(lpath + n, sizeof(lpath) - n, "%s%s",
                             n > 0 ? ":" : "", p);
                if (m < 0 || (size_t)m >= sizeof(lpath) - n)
                        break;
                n += m;
        }
        if (libcdir[0] != '\0') {
                /* the patched libc copy must win the libc.so.6 lookup */
                char withglue[PATH_MAX * 4];

                snprintf(withglue, sizeof(withglue), "%s%s%s", libcdir,
                         lpath[0] != '\0' ? ":" : "", lpath);
                setenv("LD_LIBRARY_PATH", withglue, 1);
        } else
                setenv("LD_LIBRARY_PATH", lpath, 1);

        /* working directory */
        wdir = (tracee->fs != NULL) ? tracee->fs->cwd : NULL;
        if (wdir == NULL || wdir[0] == '\0' || strcmp(wdir, "/") == 0) {
                if (chdir(root) < 0) {
                        note(tracee, ERROR, SYSTEM, "chdir('%s')", root);
                        goto fail;
                }
        } else if (wdir[0] == '/') {
                char wd[PATH_MAX];

                snprintf(wd, sizeof(wd), "%s%s", root, wdir);
                if (chdir(wd) < 0) {
                        note(tracee, WARNING, SYSTEM,
                             "无法切换到目录 '%s'，改用 '/'",
                             wdir);
                        if (chdir(root) < 0)
                                goto fail;
                }
        } else if (chdir(wdir) < 0) {
                note(tracee, WARNING, SYSTEM,
                     "无法切换到目录 '%s'，改用根文件系统目录",
                     wdir);
                if (chdir(root) < 0)
                        goto fail;
        }

        /* ptrace-only feature, now implemented for proto too: the
         * guest is exec'd from a child while this process stays
         * behind as a supervisor (see proto_supervise). */
        if (tracee->killall_on_exit) {
                /* musl fork() = legacy SYS_fork(57), trapped on
                 * Android 15 x86_64; the child execs right away, so a
                 * raw clone is a drop-in fork here (fileat.h). */
                pid_t guest = nproot_fork();

                if (guest < 0) {
                        note(tracee, WARNING, USER,
                             "无法创建监督进程，--kill-on-exit 在 proto 后端下不生效");
                } else if (guest > 0) {
                        proto_supervise(tracee, guest);
                        /* never returns */
                        _exit(0);
                } else {
                        /* child: lead a fresh process group so the
                         * supervisor can signal the whole container
                         * with one killpg(); the terminal stays where
                         * it is, the supervisor hands it over. */
                        setpgid(0, 0);
                }
        }

        /* exec the guest loader; from here on the shim is in charge */
        nb_args = 0;
        while (argv[nb_args] != NULL)
                nb_args++;
        nargv = talloc_zero_array(tracee, char *, nb_args + 6);
        if (nargv == NULL) {
                note(tracee, ERROR, INTERNAL, "无法分配内存");
                goto fail;
        }

        n = 0;
        nargv[n++] = loaderbuf;
        use_argv0 = strstr(loader_rel, "ld-linux") != NULL;
        if (use_argv0) {
                nargv[n++] = (char *)"--argv0";
                nargv[n++] = argv[0];
        }
        nargv[n++] = progbuf;
        if (applet_arg != NULL)
                nargv[n++] = (char *)applet_arg;
        for (i = 1; i < nb_args; i++)
                nargv[n++] = argv[i];
        nargv[n] = NULL;

        if (tracee->verbose >= 2)
                note(tracee, INFO, INTERNAL,
                     "proto 后端：exec %s %s（LD_PRELOAD=%s）", loaderbuf,
                     progbuf, shim);

        /* argv[0] of the loader itself is the loader path, exactly like
         * the shim's execve reroute does for chained execs */
        execv(loaderbuf, nargv);

        note(tracee, ERROR, SYSTEM, "execve(\"%s\")", loaderbuf);
        note(tracee, INFO, USER,
             "proto 后端无法启动容器，请尝试 NPROOT_BACKEND=ptrace");

fail:
        _exit(127);
}
