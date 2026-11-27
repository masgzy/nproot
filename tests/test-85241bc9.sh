#!/bin/sh
# 85241bc9: note()'s colored banner carried 8 "%s" conversions but
# only 7 arguments, so the 8th %s dereferenced a stale stack slot:
# every note() on a colored terminal (stderr is a tty) died of SIGSEGV
# before printing a byte.  CI stayed green because piped stderr keeps
# colors off.  Force the colors on, make note() print, and require the
# text to come out whole with nothing but SGR sequences stripped --
# before the fix this either crashed (aarch64) or leaked raw .text
# bytes into the message (x86_64).

set -u

PROOT=${PROOT:?}

strip_sgr() {
    sed 's/\x1b\[[0-9;]*m//g' "$1"
}

expect_note() { # expect_note <plain-file> <label>
    grep -q '^nproot 信息: proto 后端不可用（' "$1" || {
        echo "$2: note text mangled after stripping SGR:" >&2
        cat "$1" >&2
        rm -f "$1"
        exit 1
    }
}

# No rootfs of its own and no shim around: the launcher must print the
# proto-infeasible note and fall back to ptrace, exit 0.  The suite
# exports NPROOT_BACKEND=ptrace for the other tests -- unset it here so
# the note is actually reached.
OUT=$(mktemp)
STATUS=0
env -u NO_COLOR -u CLICOLOR -u NPROOT_BACKEND \
    NPROOT_FORCE_COLORS=1 COLORTERM=truecolor \
    "$PROOT" -0 /bin/true 2>"$OUT" || STATUS=$?
if [ "$STATUS" -ne 0 ]; then
    echo "truecolor run exited $STATUS:" >&2
    cat "$OUT" >&2
    rm -f "$OUT"
    exit 1
fi
strip_sgr "$OUT" > "$OUT.plain"
rm -f "$OUT"
expect_note "$OUT.plain" "truecolor"

# Same through the 16-color fallback (no COLORTERM advertised).
OUT=$(mktemp)
STATUS=0
env -u NO_COLOR -u CLICOLOR -u COLORTERM -u NPROOT_BACKEND \
    NPROOT_FORCE_COLORS=1 \
    "$PROOT" -0 /bin/true 2>"$OUT" || STATUS=$?
if [ "$STATUS" -ne 0 ]; then
    echo "16-color run exited $STATUS:" >&2
    cat "$OUT" >&2
    rm -f "$OUT"
    exit 1
fi
strip_sgr "$OUT" > "$OUT.plain"
rm -f "$OUT"
expect_note "$OUT.plain" "16-color"

rm -f "$OUT.plain"
exit 0
