#!/data/data/com.termux/files/usr/bin/bash
# nproot AVD test -- fetched over HTTP from the CI runner (10.0.2.2) and
# executed inside a real Termux session, so every line below runs under
# the emulator's genuine zygote app-seccomp filter (not the CI-replayed
# policy from proto/census).  The runner types exactly two commands into
# the Termux terminal:
#
#   curl -fsSL http://10.0.2.2:8000/avd-test.sh -o avd-test.sh
#   bash avd-test.sh
#
# Progress lands in $HOME/avd-out.txt, which the runner pulls and turns
# into the job verdict (SCRIPTED_RC / PTY_RC + the shim census lines).
# @PD_WHEEL@ is substituted by the workflow with the pd wheel filename.

OUT=$HOME/avd-out.txt
exec > "$OUT" 2>&1

echo "=== nproot AVD test begin $(date -u +%FT%TZ) ==="
uname -a
echo "Android $(getprop ro.build.version.release), ABI $(getprop ro.product.cpu.abi)"
grep -i seccomp /proc/self/status || true

# strace for the death autopsy: the runner is root (adb root), so
# ptrace is available -- this is a diagnostic aid, not the runtime
# design (nproot itself stays no-ptrace)
pkg install -y strace >/dev/null 2>&1 || true
command -v strace || echo STRACE-UNAVAILABLE

echo
echo "=== [1/5] nproot artifacts ==="
mkdir -p "$HOME/.local/bin/preload" "$PREFIX/lib"
curl -fsSL http://10.0.2.2:8000/nproot -o "$HOME/.local/bin/nproot" &&
        chmod +x "$HOME/.local/bin/nproot" ||
        echo NPROOT-DOWNLOAD-FAILED
curl -fsSL http://10.0.2.2:8000/libnproot.so \
        -o "$HOME/.local/bin/preload/libnproot.so" ||
        echo SHIM-DOWNLOAD-FAILED
ls -l "$HOME/.local/bin/nproot" "$HOME/.local/bin/preload/libnproot.so"
"$HOME/.local/bin/nproot" -V || echo "NPROOT-VERSION-FAILED"

echo
echo "=== [1b/5] host-side seccomp census (no nproot involved) ==="
# A static musl executable: every Android linker namespace accepts it
# and no libc symbol can go missing (the LD_PRELOAD route died on
# bionic's missing __errno_location).  It sweeps the filter this
# process inherited from zygote -- blocks, catchable TRAPs vs
# uncatchable KILLs -- before any guest is born.
curl -fsSL --max-time 60 http://10.0.2.2:8000/host-census \
        -o "$HOME/host-census" || echo CENSUS-DOWNLOAD-FAILED
chmod +x "$HOME/host-census" 2>/dev/null
"$HOME/host-census"
echo "HOST_CENSUS_RC=$?"

echo
echo "=== [2/5] pdi18n (python) ==="
# Emulator networking to the pkg mirrors is flaky (this step once
# stalled past the whole verdict window): bound every fetch, retry
# the package install once.
for i in 1 2; do
        timeout 420 pkg install -y python >/dev/null 2>&1 && break
        echo PKG-INSTALL-ATTEMPT-$i-FAILED
        sleep 5
done
command -v python3 || echo PYTHON-MISSING
curl -fsSL --max-time 60 "http://10.0.2.2:8000/@PD_WHEEL@" -o "$HOME/@PD_WHEEL@" ||
        echo PD-WHEEL-DOWNLOAD-FAILED
timeout 300 pip install --no-deps "$HOME/@PD_WHEEL@" || echo PD-INSTALL-FAILED
command -v pdi18n && pdi18n version || echo PDI18N-MISSING

echo
echo "=== [3/5] debian container install ==="
# The AVD egresses through a US datacenter IP: the CN docker accelerators
# pdi18n defaults to 401 on images they have not cached (observed:
# "Access denied to 'debian' (HTTP 401)").  The official hub is directly
# reachable from the runner's NAT and always carries library/debian;
# the CN default stays as the fallback for the case the hub rate-limits.
export PD_REGISTRY_URL="https://registry-1.docker.io"
echo "registry override: $PD_REGISTRY_URL"
timeout 900 pdi18n install debian || {
        echo PD-INSTALL-DEBIAN-HUB-FAILED-RETRYING-DEFAULT
        unset PD_REGISTRY_URL
        timeout 900 pdi18n install debian || echo PD-INSTALL-DEBIAN-FAILED
}
pdi18n list || true

echo
echo "=== [3b/5] direct nproot launch (bypasses the python exec chain) ==="
# pdi18n login execs into nproot, so a silent SIGSYS death could sit
# anywhere on that chain.  Run the exact command pd would run, from a
# plain sh: if this dies before nproot's own verbose output, the
# killer syscall belongs to the host-side (static musl) launch path,
# not to the guest.  The debug variables are injected INSIDE the
# `env -i` (it would otherwise wipe them before nproot sees them).
set +e
PDCMD=$(pdi18n login debian --get-proot-cmd)
echo "PDCMD: $PDCMD"
# pure bash surgery: sed's backslashes die through the quoting layers
NEWLINE=$'\n'
OLD="-i \\"
NEW="-i PROOT_VERBOSE=2 NPROOT_DEBUG=1 NPROOT_CENSUS=1 \\"
PDCMD_DEBUG=${PDCMD/"$OLD"/"$NEW"}
if [ "$PDCMD_DEBUG" = "$PDCMD" ]; then
        echo "WARN: '-i \\' not found in PDCMD; debug vars stay host-side"
fi
echo "PDCMD_DEBUG: $PDCMD_DEBUG"
# sanity: does a bare env(1) survive?  If THIS dies, the victim is
# host-side coreutils, not nproot.
env -i /bin/true
echo "BARE_ENV_RC=$?"
# under strace the last syscall before the SIGSYS death names the
# killer exactly
if command -v strace >/dev/null 2>&1; then
        strace -f -o "$HOME/direct.strace" \
                sh -c "$PDCMD_DEBUG -- /bin/bash -lc 'echo DIRECT-OK'"
        echo "DIRECT_STRACE_RC=$?"
fi
# fold the appended command INTO the guest bash so there is exactly
# one bash: pd's base command ends with "/bin/bash \\\n  -l" and the
# appended '-- /bin/bash -lc ...' made it a double bash, whose second
# exec trips the ENOEXEC edge.  Replacing the '/bin/bash + -l' tail
# with a single 'bash -lc ...' gives the same clean shape the
# scripted probe already proves works.
# strip from the trailing "/bin/bash \<newline>  -l" to the end, then
# append the single clean command
PDCMD_DEBUG=${PDCMD_DEBUG%"/bin/bash \\"*}"  /bin/bash -lc 'echo DIRECT-OK; uname -m; id -u; cat /etc/debian_version'"
echo "PDCMD_SINGLE: $PDCMD_DEBUG"
sh -c "$PDCMD_DEBUG"
echo "DIRECT_RC=$?"
set -e

echo
echo "=== [4/5] scripted probe (python exec chain; informational on x86_64) ==="
# The python chain dies on this AVD's filter (bionic fork(57)-class
# blocks bite CPython's spawn path); strace names the killer.  On the
# arm64 devices this chain works -- there is no legacy fork there.
set +e
if command -v strace >/dev/null 2>&1; then
        strace -f -o "$HOME/scripted.strace" \
                env PROOT_VERBOSE=2 pdi18n login debian -- /bin/bash -lc \
                'echo SCRIPTED_OK; uname -m; id -u; cat /etc/debian_version'
        echo "SCRIPTED_STRACE_RC=$?"
fi
PROOT_VERBOSE=2 pdi18n login debian -- /bin/bash -lc \
        'echo SCRIPTED_OK; uname -m; id -u; cat /etc/debian_version'
echo "SCRIPTED_RC=$?"

echo
echo "=== [5/5] pty probe (interactive path: terminfo + readline) ==="
# 124 = timeout with the prompt alive (success), 159 = SIGSYS death,
# 0 = clean exit, anything else = inspect the log above.
timeout 90 python3 -c 'import pty; pty.spawn(["pdi18n", "login", "debian"])'
echo "PTY_RC=$?"
set -e

echo
echo "=== AVD-TEST-DONE ==="
