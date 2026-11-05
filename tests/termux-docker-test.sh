#!/data/data/com.termux/files/usr/bin/bash
#
# Termux regression suite for the android-arm64 artifact.
#
# Runs INSIDE the termux/termux-docker:aarch64 container (native arm64
# CI runner), with the repo mounted read-only at /work and /tmp mounted
# as a read-only tmpfs -- the host-side equivalent of the Android/Termux
# layout where bionic's P_tmpdir=/tmp has no writable directory behind
# it and nproot must fall back to $PREFIX/tmp.
#
# Covers the two bugs users actually hit on device:
#   * temp-dir candidates: ro /tmp must not break the run, the glue
#     rootfs must land in $PREFIX/tmp;
#   * glue failure latch: with NO usable temp candidate the three
#     error lines print exactly once, not once per binding component.
#
# EXPECTED_HASH must carry the git describe output the binary was
# built with (same command as src/GNUmakefile's CHECK_VERSION).

set -u

PREFIX=/data/data/com.termux/files/usr
SH=$PREFIX/bin/sh
# CI mounts the repo at /work with the artifact under artifact/; the
# default is overridable so the suite can be reused elsewhere.
NPROOT=${NPROOT:-/work/artifact/nproot}
LOG=$PREFIX/tmp
PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); echo "[PASS] $1"; }
bad() { FAIL=$((FAIL+1)); echo "[FAIL] $1"; }

echo "== T0: this really is the Termux environment =="
if [ -x "$SH" ] && [ -n "${PREFIX:-}" ] && [ -x /system/bin/linker64 ]; then
    ok T0
else
    bad T0
fi

echo "== T1: --version / -V carry the built commit hash =="
V1=$("$NPROOT" --version 2>&1 | head -1)
echo "$V1"
V2=$("$NPROOT" -V 2>&1 | head -1)
case "$V1" in *"no-ptrace proot"*) ok T1a;  ;; *) bad T1a; ;; esac
case "$V1" in *"$EXPECTED_HASH"*)   ok T1b;  ;; *) bad T1b; echo "expected hash: $EXPECTED_HASH"; ;; esac
case "$V2" in *"$EXPECTED_HASH"*)   ok T1c;  ;; *) bad T1c; ;; esac

echo "== T2: read-only /tmp does not break a plain run =="
if "$NPROOT" -0 "$SH" -c 'echo SMOKE-OK' 2>"$LOG/t2.err" | grep -q SMOKE-OK; then
    ok T2
else
    bad T2
    cat "$LOG/t2.err"
fi

echo "== T3: glue rootfs lands in \$PREFIX/tmp (ro /tmp) =="
# A binding whose guest path does not exist is what forces the glue
# rootfs to be built; with the default root == / nothing is missing and
# no glue would ever be created.
OUT=$("$NPROOT" -v 1 -0 \
      -b /etc/hosts:/no/such/glue-placeholder \
      "$SH" -c 'echo FALLBACK-OK' 2>&1)
if printf '%s' "$OUT" | grep -q FALLBACK-OK; then ok "T3-run"; else bad "T3-run"; fi
GLUE=$(printf '%s' "$OUT" | grep '胶水根文件系统 =' | head -1)
echo "$GLUE"
case "$GLUE" in *"$PREFIX/tmp"*) ok T3a; ;; *) bad T3a; printf '%s\n' "$OUT" | head -20; ;; esac
if printf '%s' "$OUT" | grep -q "can't create glue rootfs"; then
    bad T3b
else
    ok T3b
fi

echo "== T4: no usable temp candidate -> latch, each error exactly once =="
# With PROOT_TMP_DIR set (authoritative, no fallback) and unusable, the
# run must degrade EXACTLY like the device report this suite regresses:
# one glue failure (latched, not one per missing path component), one
# loader-extraction failure at exec time, one hint per failure, and a
# failed execve -- the guest cannot start without the loader.
OUT=$(env PROOT_TMP_DIR=/nonexistent-dir "$NPROOT" -0 \
      -b /etc/hosts:/no/such/dir/a/b/c \
      -b /etc/hosts:/no/such/dir/d/e/f \
      "$SH" -c 'echo LATCH-RUN-OK' 2>&1)
printf '%s\n' "$OUT" | head -25
N_GLUE=$(printf '%s' "$OUT" | grep -c "can't create glue rootfs" || true)
N_TMP=$(printf '%s' "$OUT" | grep -c "can't create temporary directory" || true)
N_FILE=$(printf '%s' "$OUT" | grep -c "can't create temporary file" || true)
N_HINT=$(printf '%s' "$OUT" | grep -c "Please set PROOT_TMP_DIR" || true)
RUNS=$(printf '%s' "$OUT" | grep -c "LATCH-RUN-OK" || true)
echo "glue=$N_GLUE tmpdir=$N_TMP file=$N_FILE hint=$N_HINT ran=$RUNS"
[ "$N_GLUE" = 1 ] && ok T4a || bad T4a
[ "$N_TMP"  = 1 ] && ok T4b || bad T4b
[ "$N_FILE" = 1 ] && ok T4c || bad T4c
[ "$N_HINT" = 2 ] && ok T4d || bad T4d
[ "$RUNS"   = 0 ] && ok T4e || bad T4e

echo "== T6: no PREFIX/TMPDIR + ro /tmp -> \$HOME/.cache/nproot (recursive mkdir) =="
# The exact shape a pd-launched nproot lands in: pd's env carries no
# PREFIX, and a fresh Termux home has no .cache/ -- mkdir(2) does not
# create parents, so this used to reject every candidate and fail the
# run.  The candidate must now be created, parents included, and the
# glue rootfs must land inside it.
SAVED_HOME=${HOME:-/root}
rm -rf "$SAVED_HOME/.cache"
OUT=$(env -u PREFIX -u TMPDIR -u PROOT_TMP_DIR "$NPROOT" -v 1 -0 \
      -b /etc/hosts:/no/such/glue-placeholder \
      "$SH" -c 'echo HOMECACHE-OK' 2>&1)
if printf '%s' "$OUT" | grep -q HOMECACHE-OK; then ok "T6-run"; else bad "T6-run"; fi
GLUE6=$(printf '%s' "$OUT" | grep '胶水根文件系统 =' | head -1)
echo "$GLUE6"
case "$GLUE6" in
    *"$SAVED_HOME/.cache/nproot"*) ok T6a; ;;
    *) bad T6a; printf '%s\n' "$OUT" | head -20; ;;
esac
if printf '%s' "$OUT" | grep -q "temp directory candidate"; then
    bad T6b  # success must stay silent about rejected candidates
else
    ok T6b
fi

echo "== T7: TMPDIR=/tmp duplicate is deduped in the diagnostics =="
# With every candidate dead (/tmp ro, /work ro-mounted) the run fails,
# but /tmp must be reported exactly once even though TMPDIR repeats it,
# and the two $HOME candidates must each get a line naming their errno.
OUT=$(env -u PREFIX -u PROOT_TMP_DIR TMPDIR=/tmp HOME=/work/ro-home \
      "$NPROOT" -b /etc/hosts:/no/such/dir/a/b/c \
      "$SH" -c 'echo DEAD-OK' 2>&1)
printf '%s\n' "$OUT" | head -15
N_TOT=$(printf '%s' "$OUT" | grep -c "temp directory candidate" || true)
N_TMP=$(printf '%s' "$OUT" | grep -c "candidate '/tmp' is unusable" || true)
N_GLUE=$(printf '%s' "$OUT" | grep -c "can't create glue rootfs" || true)
[ "$N_TOT" = 3 ]  && ok T7a || bad T7a
[ "$N_TMP" = 1 ]  && ok T7b || bad T7b
[ "$N_GLUE" = 1 ] && ok T7c || bad T7c

echo "== T5: glue is cleaned up on exit =="
BEFORE=$(ls -A "$PREFIX/tmp" | wc -l)
"$NPROOT" -0 "$SH" -c 'true' >/dev/null 2>&1
AFTER=$(ls -A "$PREFIX/tmp" | wc -l)
[ "$AFTER" = "$BEFORE" ] && ok T5 || bad T5

echo "== T8: proto backend (LD_PRELOAD, no ptrace) =="
# The artifact carries the guest-libc shims in preload/ next to the
# binary; the proto backend must pick them up, run a musl guest with
# zero ptrace (TracerPid = 0) and fall back to ptrace when forced.
#
# The TracerPid probes use shell builtins ONLY (no guest awk/cat):
# the guest inherits the host PATH, which this container populates
# from Termux -- it has no awk at all -- so a PATH lookup inside the
# guest would fail with "awk: not found" even though the rootfs is
# fine (this is standard proot semantics: pd sets the guest PATH at
# login itself).  Applet execs get their own assertions T8d/T8e,
# which set PATH inside the guest first.
T8DIR=$HOME/nproot-proto
rm -rf "$T8DIR"
mkdir -p "$T8DIR/preload" "$T8DIR/rootfs"
cp "$NPROOT" "$T8DIR/nproot"
chmod +x "$T8DIR/nproot"
if [ -d /work/artifact/preload ]; then
    cp /work/artifact/preload/*.so "$T8DIR/preload/"
fi
if [ ! -e "$T8DIR/preload/libnproot-musl.so" ]; then
    echo "[SKIP] T8 (no musl shim in the artifact)"
else
    curl -fsSL --retry 2 -o "$T8DIR/alpine.tgz" \
        https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.3-aarch64.tar.gz
    echo "T8 diag: alpine.tgz = $(wc -c < "$T8DIR/alpine.tgz") bytes"
    tar -xzf "$T8DIR/alpine.tgz" -C "$T8DIR/rootfs" 2>"$LOG/t8-tar.err" \
        || echo "T8 diag: tar stderr follows"; cat "$LOG/t8-tar.err"
    # NOTE: guest /bin/sh is a symlink to /bin/busybox with a
    # guest-absolute target, so -e/-x would follow it against the
    # container root where no /bin/busybox exists; accept the link
    # itself (-L) as evidence the extraction happened.
    if [ ! -e "$T8DIR/rootfs/bin/sh" ] && [ ! -L "$T8DIR/rootfs/bin/sh" ]; then
        echo "[SKIP] T8 (guest /bin/sh missing after extraction -- infra, not nproot)"
        rm -rf "$T8DIR"
        FAIL=$((FAIL+1))
    else
        echo "T8 diag: guest files present: sh, awk, ld-musl, busybox"
        for f in usr/bin/awk lib/ld-musl-aarch64.so.1 bin/busybox; do
            [ -e "$T8DIR/rootfs/$f" ] || [ -L "$T8DIR/rootfs/$f" ] \
                || echo "T8 diag: WARNING - guest file missing: /$f"
        done
        # The container itself must expose TracerPid, or nothing below
        # means anything.
        echo "T8 diag: host TracerPid = $(awk '/^TracerPid/{print $2}' /proc/self/status)"

        # Read TracerPid with builtins only: ash `read` on the redirect,
        # `set --` to split the line, `echo` for the value.
        TP_SCRIPT='while IFS= read -r l; do set -- $l; if [ "$1" = TracerPid: ]; then echo "$2"; fi; done < /proc/self/status'

        if env NPROOT_BACKEND=proto PROOT_TMP_DIR="$PREFIX/tmp" \
            "$T8DIR/nproot" -r "$T8DIR/rootfs" /bin/sh -c 'echo PROTO-OK' \
            2>"$LOG/t8.err" | grep -q PROTO-OK; then
            ok T8a
        else
            bad T8a
            cat "$LOG/t8.err"
        fi

        TP=$(env NPROOT_BACKEND=proto PROOT_TMP_DIR="$PREFIX/tmp" \
            "$T8DIR/nproot" -r "$T8DIR/rootfs" \
            /bin/sh -c "$TP_SCRIPT" 2>"$LOG/t8b.err")
        if [ "$TP" = 0 ]; then
            ok T8b
        else
            bad T8b
            echo "TracerPid = '$TP' (stderr follows)"
            cat "$LOG/t8b.err"
            env NPROOT_BACKEND=proto NPROOT_DEBUG=1 PROOT_TMP_DIR="$PREFIX/tmp" \
                "$T8DIR/nproot" -r "$T8DIR/rootfs" /bin/sh -c "$TP_SCRIPT" 2>&1 | head -25
        fi

        TP2=$(env NPROOT_BACKEND=ptrace PROOT_TMP_DIR="$PREFIX/tmp" \
            "$T8DIR/nproot" -r "$T8DIR/rootfs" -b /proc \
            /bin/sh -c "$TP_SCRIPT" 2>"$LOG/t8c.err")
        if [ -n "$TP2" ] && [ "$TP2" != 0 ]; then
            ok T8c
        else
            bad T8c
            echo "ptrace TracerPid = '$TP2' (stderr follows)"
            cat "$LOG/t8c.err"
            env NPROOT_BACKEND=ptrace PROOT_TMP_DIR="$PREFIX/tmp" \
                "$T8DIR/nproot" -v 1 -r "$T8DIR/rootfs" -b /proc \
                /bin/sh -c "$TP_SCRIPT" 2>&1 | head -25
        fi

        # T8d: a runtime execve of a busybox applet under the proto
        # backend -- awk as a real binary, not a builtin.  PATH must
        # be set inside the guest (see the block comment above).
        if env NPROOT_BACKEND=proto PROOT_TMP_DIR="$PREFIX/tmp" \
            "$T8DIR/nproot" -r "$T8DIR/rootfs" \
            /bin/sh -c 'PATH=/bin:/usr/bin; export PATH; \
                        awk "BEGIN{print \"AWK-OK\"}"' \
            2>"$LOG/t8d.err" | grep -q AWK-OK; then
            ok T8d
        else
            bad T8d
            cat "$LOG/t8d.err"
        fi
        # T8e: same for the ptrace backend, reading /proc through the
        # binding with a real applet.
        if env NPROOT_BACKEND=ptrace PROOT_TMP_DIR="$PREFIX/tmp" \
            "$T8DIR/nproot" -r "$T8DIR/rootfs" -b /proc \
            /bin/sh -c 'PATH=/bin:/usr/bin; export PATH; \
                        grep -a TracerPid /proc/self/status' \
            2>"$LOG/t8e.err" | grep -q TracerPid; then
            ok T8e
        else
            bad T8e
            cat "$LOG/t8e.err"
        fi

        rm -rf "$T8DIR"
    fi
fi

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
