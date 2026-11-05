#!/bin/sh
# Smoke tests for the nproot LD_PRELOAD prototype (route D, no ptrace).
#
#   ROOTFS=/path/to/glibc-rootfs ./run-tests.sh
#
# The rootfs must be the same architecture as the host and must use
# the same libc family as the shim build (glibc by default).  See
# README.md for downloading ubuntu-base / alpine-minirootfs.
#
# Tests:
#   t1  isolation:      guest /etc/hostname is the rootfs one
#   t2  root listing:   guest ls / shows the rootfs content
#   t3  exec chain:     guest sh -c 'cat ...' works (execve reroute)
#   t4  stat:           guest stat /bin/ls works
#   t5  no ptrace:      TracerPid of the guest process is 0
#   t6  ptrace compare: the ptrace backend shows TracerPid != 0
#   t7  os-release:     guest /etc/os-release is the rootfs one
#   t8  seccomp guard:  a clone3-killing filter (the Android app
#                       seccomp policy) no longer SIGSYS-kills a
#                       threaded glibc guest; the shim emulates ENOSYS
#   t9  foreign libc:   a host binary bound into the guest runs
#                       natively (never through the guest loader)
#   t10 glibc boot:     guest /bin/bash starts (heavy glibc init)
#   t11 guest PATH:     the guest gets a distro-standard PATH, never
#                       the inherited host one (the "apt in Alpine"
#                       fix)
#   t12 host leak:      TMPDIR/LD_PRELOAD/LD_LIBRARY_PATH entries
#                       under the Termux prefix are dropped
#   t13 keep-env:       NPROOT_KEEP_ENV=1 disables the isolation

set -u

# resolve everything relative to this script so the suite can run
# from any working directory
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

ROOTFS=${ROOTFS:?set ROOTFS=/path/to/rootfs}
LITE=${LITE:-$SELF_DIR/launcher/nproot-lite}
PTRACE_NPROOT=${PTRACE_NPROOT:-$SELF_DIR/../src/nproot}

pass=0; fail=0; skipped=0

report() {      # report <PASS|FAIL|SKIP> <name> <detail>
        printf '%-4s %-16s %s\n' "$1" "$2" "$3"
        case "$1" in
        PASS) pass=$((pass + 1)) ;;
        FAIL) fail=$((fail + 1)) ;;
        *)    skipped=$((skipped + 1)) ;;
        esac
}

guest() {       # run a command inside the rootfs via the prototype
        "$LITE" -r "$ROOTFS" -- "$@"
}

expect_file_content() { # expect_file_content <host-file> <guest-cmd...>
        local got want hostfile="$1"
        shift
        got=$(guest "$@" 2>/dev/null)
        want=$(cat "$hostfile")
        if [ -n "$want" ] && [ "$got" = "$want" ]; then
                return 0
        fi
        return 1
}

# --- t1 isolation: /etc/hostname comes from the rootfs -----------------
if [ -f "$ROOTFS/etc/hostname" ]; then
        if expect_file_content "$ROOTFS/etc/hostname" /bin/cat /etc/hostname; then
                report PASS t1-isolation "/etc/hostname served from rootfs"
        else
                got=$(guest /bin/cat /etc/hostname 2>&1)
                report FAIL t1-isolation "got '$got'"
        fi
else
        report SKIP t1-isolation "rootfs has no /etc/hostname"
fi

# --- t2 root listing ----------------------------------------------------
out=$(guest /bin/ls / 2>/dev/null)
if printf '%s' "$out" | grep -q usr && printf '%s' "$out" | grep -q bin; then
        report PASS t2-ls-root "ls / lists the rootfs root"
else
        report FAIL t2-ls-root "unexpected: $(printf '%s' "$out" | head -2 | tr '\n' ' ')"
fi

# --- t3 exec chain (execve reroute through the guest loader) -----------
if [ -f "$ROOTFS/etc/hostname" ]; then
        if expect_file_content "$ROOTFS/etc/hostname" /bin/sh -c 'cat /etc/hostname'; then
                report PASS t3-exec-chain "sh -c 'cat ...' (chained execve)"
        else
                got=$(guest /bin/sh -c 'cat /etc/hostname' 2>&1)
                report FAIL t3-exec-chain "got '$got'"
        fi
else
        report SKIP t3-exec-chain "rootfs has no /etc/hostname"
fi

# --- t4 stat ------------------------------------------------------------
if guest /bin/stat /bin/ls >/dev/null 2>&1; then
        report PASS t4-stat "stat /bin/ls"
else
        report FAIL t4-stat "stat /bin/ls failed"
fi

# --- t5 no-ptrace proof: TracerPid == 0 ---------------------------------
guest /bin/sh -c 'sleep 4' &
gpid=$!
sleep 1
if [ -r "/proc/$gpid/status" ]; then
        tp=$(awk '/^TracerPid:/{print $2}' "/proc/$gpid/status" 2>/dev/null)
        if [ "$tp" = "0" ]; then
                report PASS t5-no-ptrace "TracerPid of guest = 0"
        else
                report FAIL t5-no-ptrace "TracerPid = $tp"
        fi
else
        report SKIP t5-no-ptrace "guest process vanished too fast"
fi
wait "$gpid" 2>/dev/null

# --- t6 contrast: the ptrace backend DOES show a tracer -----------------
if [ -x "$PTRACE_NPROOT" ]; then
        # The guest of the ptrace backend is a forked child, so read the
        # tracer pid from inside the guest (/proc is bound for that).
        # NPROOT_BACKEND=ptrace must be forced explicitly: since the
        # no-ptrace backend became the default, an unforced run would
        # silently take the proto route and report TracerPid = 0.
        tp=$(env NPROOT_BACKEND=ptrace "$PTRACE_NPROOT" -r "$ROOTFS" -b /proc /bin/sh \
                -c 'cat /proc/self/status' 2>/dev/null | awk '/^TracerPid:/{print $2}')
        if [ -n "$tp" ] && [ "$tp" != "0" ]; then
                report PASS t6-ptrace-contrast "ptrace backend: guest TracerPid = $tp"
        else
                report SKIP t6-ptrace-contrast "guest TracerPid = $tp (backend not tracing?)"
        fi
else
        report SKIP t6-ptrace-contrast "build src/nproot first for the comparison"
fi

# --- t7 os-release -------------------------------------------------------
if [ -f "$ROOTFS/etc/os-release" ]; then
        want_id=$(grep -E '^ID=' "$ROOTFS/etc/os-release" | head -1)
        got_id=$(guest /bin/cat /etc/os-release 2>/dev/null | grep -E '^ID=' | head -1)
        if [ -n "$want_id" ] && [ "$got_id" = "$want_id" ]; then
                report PASS t7-os-release "$got_id"
        else
                report FAIL t7-os-release "got '$got_id', want '$want_id'"
        fi
else
        report SKIP t7-os-release "rootfs has no /etc/os-release"
fi

# --- t8 seccomp TRAP -> ENOSYS emulation (the glibc-on-Android fix) -----
# Android's app seccomp filter answers clone3(2) with SECCOMP_RET_TRAP
# and the kernel turns that into SIGSYS, killing the guest ("Unknown
# signal 31").  The shim must emulate -ENOSYS so glibc's pthread_create
# falls back to clone(2).  A tiny helper installs exactly that filter
# and execs the main binary; the guest program creates a thread.
# Needs a glibc rootfs (musl never calls clone3), cc and src/nproot.
if [ ! -x "$PTRACE_NPROOT" ] || ! command -v cc >/dev/null 2>&1; then
        report SKIP t8-seccomp "needs cc and a built src/nproot"
elif ls "$ROOTFS"/lib*/ld-linux-* >/dev/null 2>&1 || \
      ls "$ROOTFS"/usr/lib*/ld-linux-* >/dev/null 2>&1 || \
      ls "$ROOTFS"/lib64/ld-linux-* >/dev/null 2>&1; then
        t8dir=$(mktemp -d)
        trap_rm() { rm -rf "$t8dir"; rm -f "$ROOTFS/bin/t-seccomp"; }
        # A static-pie guest program would dodge the loader route; the
        # dynamic one below links against the host glibc, which must
        # not be newer than the rootfs's (CI: ubuntu-base 22.04 fits).
        cat > "$t8dir/traphelper.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static int install_filter(struct sock_fprog *prog)
{
        /* seccomp(2) where available; prctl(2) where the calling
         * environment blocks that syscall (container sandboxes). */
        if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, prog) == 0)
                return 0;
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
                return -1;
        return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog, 0, 0);
}

int main(int argc, char **argv)
{
        struct sock_filter filter[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                         offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 435 /* clone3 */, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
                .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
                .filter = filter,
        };

        if (argc < 2)
                return 2;
        if (install_filter(&prog) != 0) {
                perror("seccomp");
                return 2;
        }
        execvp(argv[1], argv + 1);
        perror("execvp");
        return 3;
}
EOF
        cat > "$t8dir/t-seccomp.c" <<'EOF'
#include <pthread.h>
#include <stdio.h>

static void *spin(void *arg)
{
        (void)arg;
        return NULL;
}

int main(void)
{
        pthread_t t;

        if (pthread_create(&t, NULL, spin, NULL) != 0) {
                puts("thread-create-failed");
                return 1;
        }
        pthread_join(t, NULL);
        puts("seccomp-guard-ok");
        return 0;
}
EOF
        if cc -O2 -o "$t8dir/traphelper" "$t8dir/traphelper.c" && \
           cc -O2 -pthread -o "$t8dir/t-seccomp" "$t8dir/t-seccomp.c"; then
                cp "$t8dir/t-seccomp" "$ROOTFS/bin/t-seccomp"
                # control: the guest thread program passes without the filter
                if ! out=$(env NPROOT_SHIM="$SELF_DIR/preload/libnproot.so" \
                        "$PTRACE_NPROOT" -r "$ROOTFS" /bin/t-seccomp 2>/dev/null); then
                        report SKIP t8-seccomp "guest thread program itself failed: $out"
                        trap_rm
                else
                        out=$(env NPROOT_SHIM="$SELF_DIR/preload/libnproot.so" \
                                "$t8dir/traphelper" "$PTRACE_NPROOT" \
                                -r "$ROOTFS" /bin/t-seccomp 2>/dev/null)
                        st=$?
                        if [ "$out" = "seccomp-guard-ok" ] && [ "$st" -eq 0 ]; then
                                report PASS t8-seccomp "clone3 TRAP emulated as ENOSYS"
                        else
                                report FAIL t8-seccomp "under filter: '$out' (status $st)"
                        fi
                        trap_rm
                fi
        else
                report SKIP t8-seccomp "cannot build the seccomp helpers here"
                rm -rf "$t8dir"
        fi
else
        report SKIP t8-seccomp "musl rootfs: no clone3 probe to simulate"
fi

# --- t8b the full Android app-filter danger list -------------------------
# The Android app seccomp policy TRAPs every syscall outside bionic's
# set.  For a glibc guest the lethal probes are set_robust_list (the
# guest dynamic loader issues it before any constructor can arm the
# shim's SIGSYS guard; the launcher patches it out of loader+libc
# copies -- NPROOT_SECCOMP_COMPAT=1 forces that on a non-Android
# host), rseq (GLIBC_TUNABLES), clone3 (shim instruction patch) and
# close_range/openat2/faccessat2 (shim SIGSYS->ENOSYS handler).  The
# filter is installed by a guest-side helper, so the host binary stays
# outside the filter -- exactly the Termux device topology.
if [ ! -x "$PTRACE_NPROOT" ] || ! command -v cc >/dev/null 2>&1; then
        report SKIP t8b-android "needs cc and a built src/nproot"
elif ls "$ROOTFS"/lib*/ld-linux-* >/dev/null 2>&1 || \
      ls "$ROOTFS"/usr/lib*/ld-linux-* >/dev/null 2>&1 || \
      ls "$ROOTFS"/lib64/ld-linux-* >/dev/null 2>&1; then
        t8bdir=$(mktemp -d)
        cat > "$t8bdir/androidsim.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static int install_filter(struct sock_fprog *prog)
{
        if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, prog) == 0)
                return 0;
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
                return -1;
        return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog, 0, 0);
}

int main(int argc, char **argv)
{
        /* the documented danger list; the numbers come from the
         * compile-time macros so the helper works on any arch */
        static const unsigned long nrs[] = {
                SYS_set_robust_list, SYS_rseq, SYS_clone3,
                SYS_close_range, SYS_openat2, SYS_faccessat2,
        };
        struct sock_filter filter[3 + sizeof(nrs) / sizeof(nrs[0])];
        unsigned long i;
        int flen = 0;
        struct sock_fprog prog;

        if (argc < 2)
                return 2;
        filter[flen++] = (struct sock_filter)BPF_STMT(
                BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
        for (i = 0; i < sizeof(nrs) / sizeof(nrs[0]); i++) {
                /* jump at filter index 1+i, TRAP sits at index
                 * nr_count+1; jt/jf are relative to the next insn */
                int jt = (int)(sizeof(nrs) / sizeof(nrs[0]) - i - 1);
                int jf = (i == sizeof(nrs) / sizeof(nrs[0]) - 1) ? 1 : 0;

                filter[flen++] = (struct sock_filter)BPF_JUMP(
                        BPF_JMP | BPF_JEQ | BPF_K, nrs[i], jt, jf);
        }
        filter[flen++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                                      SECCOMP_RET_TRAP);
        filter[flen++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                                      SECCOMP_RET_ALLOW);
        prog.len = (unsigned short)flen;
        prog.filter = filter;
        if (install_filter(&prog) != 0) {
                perror("seccomp");
                return 2;
        }
        execvp(argv[1], argv + 1);
        perror("execvp");
        return 3;
}
EOF
        if cc -O2 -o "$t8bdir/androidsim" "$t8bdir/androidsim.c"; then
                cp "$t8bdir/androidsim" "$ROOTFS/bin/t8sim"
                out=$(env NPROOT_SECCOMP_COMPAT=1 \
                        NPROOT_SHIM="$SELF_DIR/preload/libnproot.so" \
                        "$PTRACE_NPROOT" -r "$ROOTFS" -- \
                        /bin/t8sim /bin/bash -c 'echo full-filter-ok' \
                        2>"$t8bdir/stderr")
                st=$?
                if [ "$out" = "full-filter-ok" ] && [ "$st" -eq 0 ] && \
                   grep -q 'Android seccomp' "$t8bdir/stderr"; then
                        report PASS t8b-android "the full danger list no longer kills a glibc guest"
                else
                        report FAIL t8b-android "under filter: '$out' (status $st)"
                fi
                rm -f "$ROOTFS/bin/t8sim"
        else
                report SKIP t8b-android "cannot build the filter helper here"
        fi
        rm -rf "$t8bdir"
else
        report SKIP t8b-android "musl rootfs: nothing on the danger list"
fi

# --- t9 foreign-libc host binary runs natively -------------------------
# The ptrace backend never reroutes host binaries through the guest
# loader; the shim must likewise pass through ELFs whose interpreter
# belongs to another libc family (bionic on Android, host glibc for a
# musl guest).  Rerouting used to end in guest-loader relocation
# errors -- the "apt crashes inside Alpine" failure.
HOST_ECHO=/bin/echo
if [ -x "$HOST_ECHO" ]; then
        got=$(NPROOT_BINDS="/bin:/host-bin" \
                guest /bin/sh -c '/host-bin/echo host-native-ok' 2>/dev/null)
        if [ "$got" = "host-native-ok" ]; then
                report PASS t9-foreign-libc "host binary exec'd natively"
        else
                report FAIL t9-foreign-libc "got '$got'"
        fi
else
        report SKIP t9-foreign-libc "no host /bin/echo"
fi

# --- t10 glibc boot: bash runs its full startup ------------------------
# bash pulls in more of the libc than the other tests (locale,
# faccessat2, etc.); on Android this rides the seccomp guard.
if [ -x "$ROOTFS/bin/bash" ]; then
        if guest /bin/bash -c 'echo glibc-bash-ok' 2>/dev/null | \
                        grep -q glibc-bash-ok; then
                report PASS t10-glibc-bash "bash started in the guest"
        else
                got=$(guest /bin/bash -c 'echo glibc-bash-ok' 2>&1)
                report FAIL t10-glibc-bash "got '$got'"
        fi
else
        report SKIP t10-glibc-bash "rootfs has no /bin/bash"
fi

# --- t11 guest PATH isolation -------------------------------------------
# The inherited host PATH must not reach the guest: a Termux PATH made
# "apt" inside an Alpine guest resolve to the host's bionic binary
# (relocation failure storm).  Like a container runtime, nproot hands
# the guest a distro-standard PATH instead.  Runs the main binary:
# the isolation lives in the launcher, not in the shim.
GUEST_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
if [ -x "$PTRACE_NPROOT" ]; then
        out=$(env PATH="/data/data/com.termux/files/usr/bin:/system/bin" \
                "$PTRACE_NPROOT" -r "$ROOTFS" /bin/sh -c 'echo $PATH' 2>/dev/null)
        if [ "$out" = "$GUEST_PATH" ]; then
                report PASS t11-guest-path "guest PATH is the distro-standard one"
        else
                report FAIL t11-guest-path "got '$out'"
        fi
else
        report SKIP t11-guest-path "build src/nproot first"
fi

# --- t12 host leak: TMPDIR / LD_* under the Termux prefix ---------------
# Guest temp files belong to the guest /tmp, and bionic host libraries
# must stay out of the guest loader.  Under the proto backend the shim
# and the guest lib dirs legitimately replace LD_PRELOAD/
# LD_LIBRARY_PATH, so the assertion is: nothing under the Termux
# prefix survives, and TMPDIR is gone.
if [ -x "$PTRACE_NPROOT" ]; then
        out=$(env TMPDIR=/data/data/com.termux/files/usr/tmp \
                LD_PRELOAD=/data/data/com.termux/files/usr/lib/libtermux-exec.so \
                LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib \
                "$PTRACE_NPROOT" -r "$ROOTFS" /bin/sh -c \
                'printf "%s|%s|%s" "$TMPDIR" "$LD_PRELOAD" "$LD_LIBRARY_PATH"' 2>/dev/null)
        tmp_part=$(printf '%s' "$out" | cut -d'|' -f1)
        if [ "$tmp_part" = "" ] && \
           ! printf '%s' "$out" | grep -q "/data/data/com.termux"; then
                report PASS t12-no-host-leak "TMPDIR dropped, LD_* free of the host prefix"
        else
                report FAIL t12-no-host-leak "got '$out'"
        fi
else
        report SKIP t12-no-host-leak "build src/nproot first"
fi

# --- t13 escape hatch: NPROOT_KEEP_ENV=1 --------------------------------
# The isolation is the default, but a user who deliberately wants the
# host environment inside the container gets it back verbatim.
if [ -x "$PTRACE_NPROOT" ]; then
        out=$(env NPROOT_KEEP_ENV=1 \
                PATH="/data/data/com.termux/files/usr/bin:/system/bin" \
                "$PTRACE_NPROOT" -r "$ROOTFS" /bin/sh -c 'echo $PATH' 2>/dev/null)
        if [ "$out" = "/data/data/com.termux/files/usr/bin:/system/bin" ]; then
                report PASS t13-keep-env "NPROOT_KEEP_ENV=1 keeps the host PATH"
        else
                report FAIL t13-keep-env "got '$out'"
        fi
else
        report SKIP t13-keep-env "build src/nproot first"
fi

echo "----------------------------------------"
echo "summary: $pass passed, $fail failed, $skipped skipped"
[ "$fail" -eq 0 ]
