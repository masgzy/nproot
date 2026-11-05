#!/usr/bin/env python3
"""把 qemu -strace 输出与 Android app 白名单做差集：
按时间顺序列出 guest 发起过、但 Android app 策略禁止的 syscall。
这些就是真机上会 SIGSYS 的候选，第一个出现的就是最可能死因。
"""
import json
import os
import re
import sys
from collections import OrderedDict

BASE = os.path.dirname(os.path.abspath(__file__))
pol = json.load(open(os.environ.get(
        "POLICY_JSON", os.path.join(BASE, "policies", "policies.json"))))
ALLOWED = {v: set(pol[v].keys()) for v in pol}


def parse_strace(path):
    """返回 [(lineno, name)]，保留顺序与重复。"""
    seq = []
    pat = re.compile(r"^\d+ ([A-Za-z0-9_]+)\(")
    with open(path, errors="replace") as f:
        for i, line in enumerate(f, 1):
            m = pat.match(line)
            if m:
                seq.append((i, m.group(1)))
    return seq


def main():
    paths = sys.argv[1:]
    seen = OrderedDict()
    for p in paths:
        for lineno, name in parse_strace(p):
            if name not in seen:
                seen[name] = (p, lineno)
    # qemu 对无法识别的 syscall 打印为数字或 '?'
    print("== guest 发起过的全部 syscall: %d 种 ==" % len(seen))
    blocked_versions = {}
    for name, (p, lineno) in seen.items():
        blocked_in = sorted(v for v in ALLOWED if name not in ALLOWED[v])
        blocked_versions[name] = blocked_in
    danger = {n: b for n, b in blocked_versions.items() if b}
    print("== 其中 Android 12-15 至少一个版本会拦的（按首次出现顺序）==")
    for name, (p, lineno) in seen.items():
        if name in danger:
            print("  %-22s 首现 %s:%d  会拦的版本: %s"
                  % (name, p.split("/")[-1], lineno,
                     ",".join(danger[name]) if danger[name] else "无"))
    print("== 所有版本都拦（真机必死项）==")
    allv = [str(v) for v in ["12", "13", "14", "15"]]
    for name, b in danger.items():
        if all(v in b for v in allv):
            print("  " + name)


if __name__ == "__main__":
    main()
