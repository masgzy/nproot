#!/usr/bin/env python3
"""生成 Android 各版本 aarch64 app seccomp 白名单（复用 bionic genseccomp 逻辑）。

输出 /tmp/ah/policies.json: {"12": {name: {"a": aarch64_nr, "x": x86_64_nr}}, ...}
arm64 nr 来自内核 UAPI 头；x86_64 nr 来自主机 UAPI 头（qemu-aarch64 把
guest syscall 翻译成主机同名词用，便于在 x86_64 沙箱里装过滤器）。
"""
import json
import os
import re
import subprocess
import sys
import tempfile

AH = os.environ.get("CENSUS_BASE", "/tmp/ah")
VERSIONS = ["12", "13", "14", "15", "16"]
ARM64_UAPI = "/tmp/ah/dl/ex/usr/lib/linux/uapi/arm64"
X86_UAPI = "/tmp/ah/dl/ex/usr/include/x86_64-linux-gnu"

sys.path.insert(0, "/tmp/ah/bionic-12/libc/tools")
from gensyscalls import SysCallsTxtParser  # noqa: E402


def parse_list(path, arch):
    parser = SysCallsTxtParser()
    parser.parse_open_file(open(path))
    return {x["name"] for x in parser.syscalls if x.get(arch)}


def preprocess_syscalls_txt(path):
    """android16 起签名行去掉了返回类型（'swapoff(const char*) all'），
    且用 'all' 标记全架构；老解析器（android12 自带的）只认
    'int name:alias(params) archs'。统一规范化成老格式。"""
    import re as _re
    out = path + ".compat"
    full = "arm64,arm,x86,x86_64,lp32,lp64"  # 老解析器不认 riscv64
    with open(path) as f, open(out, "w") as g:
        for line in f:
            s = line.rstrip("\n")
            if s.lstrip().startswith("#") or not s.strip():
                g.write(line)
                continue
            # 新格式：[alias:]name(params) archs  —— 前面没有返回类型
            m = _re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_|:]*)\s*\((.*)\)\s*([A-Za-z0-9_,\s]+?)\s*$", s)
            if m and not _re.match(r"^\s*\w+\s+[A-Za-z_][A-Za-z0-9_|:]*\s*\(", s):
                lead, name, params, archs = m.groups()
                archs = archs.strip()
                if archs == "all":
                    archs = full
                g.write("%sint %s(%s) %s\n" % (lead, name, params, archs))
                continue
            # 'all' 出现在老格式行尾的情况
            s2 = _re.sub(r"(\)\s*)all\s*$", r"\1" + full, s)
            g.write(s2 + "\n")
    return out


def parse_list_compat(path, arch):
    try:
        s = parse_list(path, arch)
        if s:
            return s
    except Exception:
        pass
    return parse_list(preprocess_syscalls_txt(path), arch)


def allowed_set(version):
    libc = os.path.join(AH, "bionic-%s" % version, "libc")
    base = parse_list_compat(os.path.join(libc, "SYSCALLS.TXT"), "arm64")
    allow = set()
    block = set()
    for fn in ("SECCOMP_ALLOWLIST_APP.TXT", "SECCOMP_ALLOWLIST_COMMON.TXT"):
        allow |= parse_list_compat(os.path.join(libc, fn), "arm64")
    for fn in ("SECCOMP_BLOCKLIST_APP.TXT", "SECCOMP_BLOCKLIST_COMMON.TXT"):
        block |= parse_list_compat(os.path.join(libc, fn), "arm64")
    # genseccomp.merge_names: (base - blocklist) | allowlist
    return (base - block) | allow


def nr_map(uapi_incs, probe_names, extra_defs=()):
    """gcc -E -dM 提取 __NR_* 定义。"""
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write("#include <asm/unistd.h>\n")
        for n in probe_names:
            f.write("int x_%s = __NR_%s;\n" % (n, n))
        path = f.name
    cmd = ["gcc", "-E", "-dM", "-nostdinc"]
    for inc in uapi_incs:
        cmd += ["-I", inc]
    for d in extra_defs:
        cmd += ["-D" + d]
    cmd += [path]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        sys.stderr.write(out.stderr)
        raise RuntimeError("gcc -E failed")
    nrs = {}
    for line in out.stdout.splitlines():
        m = re.match(r"#define __NR_([A-Za-z0-9_]+) (.+)$", line)
        if m:
            try:
                nrs[m.group(1)] = int(m.group(2), 0)
            except ValueError:
                pass
    os.unlink(path)
    return nrs


def main():
    policies = {}
    all_names = set()
    for v in VERSIONS:
        s = allowed_set(v)
        policies[v] = sorted(s)
        all_names |= s
        print("android%s: %d allowed" % (v, len(s)), file=sys.stderr)
    names = sorted(all_names)
    a64 = nr_map([ARM64_UAPI], names)
    x64 = nr_map([X86_UAPI], names, ["_GNU_SOURCE"])
    missing_a = [n for n in names if n not in a64]
    missing_x = [n for n in names if n not in x64]
    print("no aarch64 nr:", missing_a, file=sys.stderr)
    print("no x86_64 nr:", missing_x, file=sys.stderr)
    out = {}
    for v in VERSIONS:
        out[v] = {}
        for n in policies[v]:
            out[v][n] = {"a": a64.get(n), "x": x64.get(n)}
    with open(os.path.join(AH, "policies.json"), "w") as f:
        json.dump(out, f, indent=0)
    # 交集（所有版本都允许的）与差集分析
    common = set.intersection(*[set(policies[v]) for v in VERSIONS])
    print("common across 12-16: %d" % len(common), file=sys.stderr)
    for v in VERSIONS:
        only = set(policies[v]) - common
        if only:
            print("android%s extra: %s" % (v, sorted(only)), file=sys.stderr)


if __name__ == "__main__":
    main()
