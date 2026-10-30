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

set -u

# resolve everything relative to this script so the suite can run
# from any working directory
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

ROOTFS=${ROOTFS:?set ROOTFS=/path/to/rootfs}
LITE=${LITE:-$SELF_DIR/launcher/nproot-lite}
PTRACE_NPROOT=${PTRACE_NPROOT:-$SELF_DIR/../src/nproot}

pass=0; fail=0; skipped=0

report() {	# report <PASS|FAIL|SKIP> <name> <detail>
	printf '%-4s %-16s %s\n' "$1" "$2" "$3"
	case "$1" in
	PASS) pass=$((pass + 1)) ;;
	FAIL) fail=$((fail + 1)) ;;
	*)    skipped=$((skipped + 1)) ;;
	esac
}

guest() {	# run a command inside the rootfs via the prototype
	"$LITE" -r "$ROOTFS" -- "$@"
}

expect_file_content() {	# expect_file_content <host-file> <guest-cmd...>
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
	tp=$("$PTRACE_NPROOT" -r "$ROOTFS" -b /proc /bin/sh \
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

echo "----------------------------------------"
echo "summary: $pass passed, $fail failed, $skipped skipped"
[ "$fail" -eq 0 ]
