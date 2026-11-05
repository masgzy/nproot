/* filter_parent.c - test harness: install a synthetic Android-style
 * seccomp policy, then exec the payload.
 *
 *   filter_parent trap=39 kill=110 -- payload args...
 *
 * trap=N: SECCOMP_RET_TRAP for syscall N (handler-savable)
 * kill=N: SECCOMP_RET_KILL_THREAD for syscall N (handler-proof)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

struct bpf_insn {
        unsigned short code;
        unsigned char jt, jf;
        unsigned int k;
};
struct fprog {
        unsigned short len;
        struct bpf_insn *filter;
};

#ifndef SYS_seccomp
#define SYS_seccomp 317
#endif

/* x86_64 syscall numbers */
#define NR_RT_SIGRETURN 15
#define NR_EXIT_GROUP   231

static struct bpf_insn prog[64];

static void add_rule(int nr, unsigned int action, int *p)
{
        prog[*p] = (struct bpf_insn){ 0x15, 0, 1, (unsigned)nr };
        (*p)++;
        prog[*p] = (struct bpf_insn){ 0x06, 0, 0, action };
        (*p)++;
}

int main(int argc, char **argv)
{
        struct fprog fprog;
        int p = 0, i;

        if (argc < 4 || strcmp(argv[1], "--") == 0) {
                fprintf(stderr, "usage: filter_parent trap=N kill=N -- cmd\n");
                return 2;
        }
        prog[p++] = (struct bpf_insn){ 0x20, 0, 0, 0 };   /* ld nr */
        for (i = 1; i < argc; i++) {
                if (strcmp(argv[i], "--") == 0)
                        break;
                if (!strncmp(argv[i], "trap=", 5))
                        add_rule(atoi(argv[i] + 5), 0x00030000u, &p);
                else if (!strncmp(argv[i], "kill=", 5))
                        add_rule(atoi(argv[i] + 5), 0x00080000u, &p);
        }
        /* always allow the syscalls the harness itself needs */
        add_rule(NR_RT_SIGRETURN, 0x7fff0000u, &p);
        add_rule(NR_EXIT_GROUP, 0x7fff0000u, &p);
        prog[p++] = (struct bpf_insn){ 0x06, 0, 0, 0x7fff0000u }; /* ALLOW */

        fprog.len = (unsigned short)p;
        fprog.filter = prog;

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                perror("prctl(NNP)");
                return 2;
        }
        if (syscall(SYS_seccomp, 1, 0, &fprog) != 0) {
                perror("seccomp(SET_MODE_FILTER)");
                return 2;
        }
        execvp(argv[i + 1], argv + i + 1);
        perror("execvp");
        return 2;
}
