/* stub_probe.c - reproduce the device death mechanism through real
 * glibc syscall stubs (patchable "mov eax,NR; syscall" pairs), inside
 * the all-signals-blocked window glibc's fork/posix_spawn creates.
 *
 * With only the SIGSYS guard: the trap inside the blocked window
 * resets the disposition; the mask restore at the end delivers SIGSYS
 * and kills the process (rc 159).  With the shield's hardened stubs
 * the blocked syscalls return -ENOSYS without any signal.
 *
 * argv[1] "uid": only issue the setuid stub (a KILL-action
 * sentinel); default issues getppid then setuid.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char **argv)
{
        sigset_t all, empty;
        long r1 = 0, r2;
        int both = !(argc > 1 && strcmp(argv[1], "uid") == 0);

        sigfillset(&all);
        sigemptyset(&empty);
        if (sigprocmask(SIG_SETMASK, &all, NULL) != 0) {
                perror("sigprocmask");
                return 2;
        }
        if (both)
                r1 = getppid();         /* stub: mov eax,110; syscall */
        r2 = setuid(0);         /* stub: mov eax,105; syscall (KILL'd) */
        printf("getppid -> %ld, setuid -> %ld\n", r1, r2);
        fflush(stdout);
        /* the glibc fork/posix_spawn window ends with a mask restore */
        sigprocmask(SIG_SETMASK, &empty, NULL);
        printf("ALIVE\n");
        fflush(stdout);
        return 0;
}
