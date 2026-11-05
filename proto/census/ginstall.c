/* ginstall.c — guest 侧 seccomp 白名单安装器（aarch64）。
 * 在 qemu 用户态 guest 里运行：读入 aarch64 nr 白名单，安装过滤器，
 * 可选安装 SIGSYS→ENOSYS 记录处理器（emul），然后 exec 目标命令。
 *
 * 用法: ginstall --policy /path/nrs.txt [--mode emul|strict|kill] -- cmd ...
 * TRAP 记录写到环境变量 CENSUS_LOG 指定的文件（guest 路径）。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <limits.h>
#include <sys/syscall.h>

#define MAX_NRS 2048
#define CHUNK 200

static unsigned int g_nrs[MAX_NRS];
static size_t g_count;
static int g_logfd = -1;

static void lprintf(const char *fmt, ...)
{
        if (g_logfd < 0)
                return;
        char buf[256];
        va_list ap;
        va_start(ap, fmt);
        int n = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (n > 0)
                write(g_logfd, buf, (size_t)n);
}

static int nr_cmp(const void *a, const void *b)
{
        unsigned int x = *(const unsigned int *)a, y = *(const unsigned int *)b;
        return x < y ? -1 : x > y ? 1 : 0;
}

static void load_policy(const char *path)
{
        FILE *f = fopen(path, "r");
        if (!f) {
                perror(path);
                exit(2);
        }
        unsigned int v;
        while (fscanf(f, "%u", &v) == 1 && g_count < MAX_NRS)
                g_nrs[g_count++] = v;
        fclose(f);
        qsort(g_nrs, g_count, sizeof(g_nrs[0]), nr_cmp);
        size_t w = 0;
        for (size_t i = 0; i < g_count; i++)
                if (w == 0 || g_nrs[w - 1] != g_nrs[i])
                        g_nrs[w++] = g_nrs[i];
        g_count = w;
}

/* 与 shim L2 同构：记录被拦 nr 并把返回寄存器改成 -ENOSYS */
static void sigsys_emul(int sig, siginfo_t *si, void *uctx)
{
        (void)sig;
        int nr = si->si_syscall;
        lprintf("TRAP nr=%d arch=%d\n", nr, si->si_arch);
        ucontext_t *uc = uctx;
#if defined(__aarch64__)
        uc->uc_mcontext.regs[0] = (unsigned long)-ENOSYS;
#elif defined(__x86_64__)
        uc->uc_mcontext.gregs[REG_RAX] = (greg_t)-ENOSYS;
#else
#error arch
#endif
}

int main(int argc, char **argv)
{
        int mode = 0;
        const char *policy = NULL;
        int i = 1;
        for (; i < argc; i++) {
                if (!strcmp(argv[i], "--policy")) {
                        policy = argv[++i];
                } else if (!strcmp(argv[i], "--mode")) {
                        const char *m = argv[++i];
                        mode = !strcmp(m, "strict") ? 1
                                       : !strcmp(m, "kill") ? 2 : 0;
                } else if (!strcmp(argv[i], "--")) {
                        i++;
                        break;
                } else {
                        break;
                }
        }
        if (!policy || i >= argc) {
                fprintf(stderr, "usage: %s --policy F [--mode M] -- cmd\n",
                        argv[0]);
                return 2;
        }
        const char *logpath = getenv("CENSUS_LOG");
        if (logpath) {
                g_logfd = open(logpath, O_WRONLY | O_CREAT | O_APPEND, 0644);
                /* 失败不致命：记录不了照样普查（结果由退出码体现） */
        }
        load_policy(policy);

        if (mode == 0) {
                struct sigaction sa;
                memset(&sa, 0, sizeof(sa));
                sa.sa_sigaction = sigsys_emul;
                sa.sa_flags = SA_SIGINFO | SA_NODEFER;
                sigemptyset(&sa.sa_mask);
                if (sigaction(SIGSYS, &sa, NULL) != 0) {
                        perror("sigaction");
                        return 2;
                }
        }

        size_t chunks = (g_count + CHUNK - 1) / CHUNK;
        static struct sock_filter ins[1 + MAX_NRS + (MAX_NRS + CHUNK - 1) / CHUNK + 1];
        size_t k = 0;
        ins[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                offsetof(struct seccomp_data, nr));
        for (size_t c = 0; c < chunks; c++) {
                size_t begin = c * CHUNK, end = begin + CHUNK;
                if (end > g_count)
                        end = g_count;
                size_t n_c = end - begin;
                for (size_t j = 0; j < n_c; j++) {
                        unsigned int jt = (unsigned int)(n_c - j - 1);
                        unsigned int jf = (j == n_c - 1) ? 1u : 0u;
                        ins[k++] = (struct sock_filter)BPF_JUMP(
                                BPF_JMP | BPF_JEQ | BPF_K, g_nrs[begin + j],
                                jt, jf);
                }
                ins[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                                        SECCOMP_RET_ALLOW);
        }
        unsigned int deny = (mode == 2) ? SECCOMP_RET_KILL_PROCESS
                                        : (SECCOMP_RET_TRAP | 0);
        ins[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, deny);

        struct sock_fprog prog = { .len = (unsigned short)k, .filter = ins };
        if (g_logfd >= 0) {
                lprintf("installed nrs=%zu mode=%d\n", g_count, mode);
                /* 日志 fd 跨 exec 保持打开 */
                int flags = fcntl(g_logfd, F_GETFD);
                fcntl(g_logfd, F_SETFD, flags & ~FD_CLOEXEC);
        }
        if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == 0)
                ;
        else if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
                 prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0)
                ;
        else {
                perror("seccomp install");
                return 3;
        }
        /* Inside an nproot proto session the program must go through
         * the (patched) guest loader exactly like the shim's execve
         * reroute does -- otherwise a statically linked helper would
         * execve(2) straight into the host's binary. */
        const char *loader = getenv("NPROOT_LOADER");
        char rooted[PATH_MAX];
        const char *progpath = argv[i];

        /* the guest loader has no path translation: give it the
         * rootfs-prefixed program path, exactly what the launcher
         * hands it on the device */
        {
                const char *root = getenv("NPROOT_ROOT");

                if (root != NULL && root[0] != '\0' && progpath[0] == '/') {
                        snprintf(rooted, sizeof(rooted), "%s%s", root,
                                 progpath);
                        progpath = rooted;
                }
        }
        if (loader != NULL && loader[0] != '\0') {
                /* ld.so argv convention: argv[0] = the loader itself,
                 * argv[1] = the program (same shape the shim's execve
                 * reroute builds). */
                char **nargv = malloc((size_t)(argc - i + 2)
                                      * sizeof(*nargv));
                int n = 0, k;

                if (nargv == NULL) {
                        perror("malloc");
                        return 127;
                }
                nargv[n++] = (char *)loader;
                nargv[n++] = (char *)progpath;
                for (k = i + 1; argv[k] != NULL; k++)
                        nargv[n++] = argv[k];
                nargv[n] = NULL;
                execv(loader, nargv);
                perror("execv loader");
        }
        execvp(argv[i], argv + i);
        perror("execvp");
        return 127;
}
