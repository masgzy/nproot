# nproot

<div align="center">

**n**o-**p**trace proot · **neo** proot

一个不依赖 `ptrace(2)` 的 PRoot 替代实现，面向 Android 与 Linux。

[![Tests](https://github.com/masgzy/nproot/actions/workflows/tests.yml/badge.svg)](https://github.com/masgzy/nproot/actions/workflows/tests.yml)
[![nproot CI](https://github.com/masgzy/nproot/actions/workflows/nproot-ci.yml/badge.svg)](https://github.com/masgzy/nproot/actions/workflows/nproot-ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL%20v3%2B-blue.svg)](COPYING)
[![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Linux-informational)](#构建)
[![Arch](https://img.shields.io/badge/arch-arm64%20%7C%20arm%20%7C%20x86__64-success)](#构建)
[![Language](https://img.shields.io/badge/language-C11-informational)](#构建)

</div>

---

## 这是什么

nproot 是 [termux/proot](https://github.com/termux/proot)（上游
[proot-me/proot](https://github.com/proot-me/proot)）的分支，目标是在
保留 proot 全部语义（无 root 的 chroot / mount --bind / binfmt_misc）
的同时，**摆脱对 `ptrace(2)` 的依赖**：

- proot 的 ptrace 模型对每syscall 付出约两次上下文切换；
- 部分厂商内核对 ptrace 有限制（`PROOT_NO_SECCOMP` 的存在就是证据）。

两种解读都成立：**no-ptrace proot**，或者 **neo proot**。

> 当前 `main` 的核心仍是继承自 termux/proot 的 **ptrace 后端**（作为
> 兼容基线与旧内核逃生门保留）。无 ptrace 的部分以三个孵化组件落地，
> 其中**路线 D 原型已在 glibc/musl 双 rootfs 上 7/7 测试通过、实测零
> ptrace**（见下文"组件总览"）。

## 组件总览

| 组件 | 状态 | 说明 |
|---|---|---|
| `src/`（ptrace 后端） | ✅ 继承并维护 | 与 termux/proot master 同步，drop-in 兼容 |
| `spike/` | ✅ 已实测 | 内核机制探针：unotify ✓ / RET_TRAP ✓（2/2 通过）|
| `src/backend/` | ✅ 骨架 | 可插拔拦截后端接口 v0 + 双后端参考实现（demo 2/2 通过）|
| `proto/` | ✅ 已实测 | **LD_PRELOAD 无 ptrace 原型**：glibc/musl rootfs 双 7/7 |
| `docs/BACKENDS.md` | 📋 | 无 ptrace 四条路线的设计文档与路线图 |

## 快速开始

### 构建（ptrace 后端，桌面 Linux）

```sh
# Debian/Ubuntu
sudo apt install build-essential libtalloc-dev
make -C src -j"$(nproc)"
./src/nproot --version
```

```sh
# Alpine/musl（额外需要 bsd-compat-headers 提供 sys/queue.h）
sudo apk add build-base talloc-dev bsd-compat-headers
```

### 构建（Android / Termux，NDK）

```sh
# 参考 .github/workflows/nproot-ci.yml 的 android-ndk job：
# NDK clang + 交叉编译 talloc（含 libtalloc.a）+ make CC=... TALLOC_LINK=...
```

CI 产物把 talloc **静态链接**进二进制，loader 也默认内嵌
（单文件自包含，解压即用）；未设置 `PROOT_TMP_DIR` 时会自动回退到
`$PREFIX/tmp`（Android 没有 `/tmp`）。Termux 本地
编译同样可以静态化——`pkg install libtalloc` 自带
`$PREFIX/lib/libtalloc.a`（≥2.5.0）：

```sh
pkg install clang make libtalloc
make -C src -j"$(nproc)" \
  CPPFLAGS="-D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Isrc -I$PREFIX/include" \
  TALLOC_LINK="-l:libtalloc.a"
```

### 使用（drop-in 兼容）

```sh
src/nproot -r ~/rootfs/ubuntu -0 /bin/sh
# 所有 PROOT_* 环境变量与 CLI 参数保持兼容
```

### 无 ptrace 原型

```sh
make -C proto
ROOTFS=/path/to/rootfs ./proto/run-tests.sh   # 7 项测试
NPROOT_DEBUG=1 ./proto/launcher/nproot-lite -r /path/to/rootfs -- /bin/ls /
```

## 无 ptrace 技术路线（摘要）

| 路线 | 机制 | 结论 |
|---|---|---|
| A. seccomp user-notify | 监听者伪造返回值/拒绝 | 可承载 fake_id0；**不能**改参数 → 无路径翻译 |
| B. RET_TRAP + 自研 execve | SIGSYS 处理器改寄存器 + loader-based exec | 终态方案（gVisor systrap 同思路）|
| C. 混合 | seccomp 热路径 + ptrace 仅 exec 边界 | 最务实 MVP |
| D. LD_PRELOAD 进程内翻译 | libc 符号插入 + 用户态符号链接/她Bang/exec 解析 | **已作为默认后端接入主二进制**（`src/proto/`）|

完整分析与内核语义发现见 **[docs/BACKENDS.md](docs/BACKENDS.md)**，
探针实测见 **[spike/README.md](spike/README.md)**，
原型实测见 **[proto/README.md](proto/README.md)**。

## 后端选择（proto 默认，ptrace 保底）

自 Phase 1 起，nproot 的**默认后端是无 ptrace 的 proto**：guest 经自己的
动态加载器启动，路径翻译由 `LD_PRELOAD` 注入的 shim 在 guest 进程内完成
（每 syscall 零次上下文切换，`TracerPid` 恒为 0）。无法承载时自动回退
ptrace 并打印原因：

```
NPROOT_BACKEND=auto    # 默认：proto 可行则 proto，否则 ptrace（打印原因）
NPROOT_BACKEND=proto   # 强制 proto，不可行直接报错
NPROOT_BACKEND=ptrace  # 强制 ptrace（旧行为）
```

proto 后端当前支持：`-r/-R/-S`、`-w`、`-b` 绑定（含 `/proc /dev /sys`
共享）、`-0`（libc 级 fake-root）；不支持：`-q`（qemu）、32 位 guest、
静态链接 rootfs——这些场景自动回退。shim 查找顺序：`$NPROOT_SHIM` →
`<二进制目录>/preload/` → 内嵌 blob（`make EMBED_SHIM=both`）。`nproot -V`
会自报后端状态。

## 目录结构

```
├── src/            # 核心源码（ptrace 后端 + proto 后端 + backend 骨架）
│   ├── proto/      # proto 后端：启动器 + NPROOT_BACKEND 选择
│   └── backend/    # 可插拔后端接口 v0（demo 可独立构建运行）
├── spike/          # 内核机制可行性探针
├── proto/          # LD_PRELOAD shim 源码 + 独立原型（nproot-lite）+ 测试
├── docs/           # BACKENDS.md 设计文档
└── tests/          # 上游测试套件（make -C tests check）
```

## Android 适配注意事项

- **W^X**：targetSdk ≥ 29 禁止 `execve()` 应用数据目录文件
  （Termux 因此钉在 28）。nproot 本体建议打包进 jniLibs
  （`libnproot.so`）；loader-based exec 走 mmap PROT_EXEC，
  SELinux 权限项不同，需真机验证。
- **内核版本**：user-notify 需 5.0+、`pidfd_getfd` 需 5.6+；
  旧设备自动回退 ptrace 后端。
- **16KB page**（Android 15 部分设备）：loader 与补丁器需检查页大小假设。
- 厂商内核 seccomp 差异是常态（`PROOT_NO_SECCOMP` 的成因），
  ptrace 逃生门因此永久保留。

## 参与贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。提交遵循 `scope: summary`
规范，测试先行。

## 许可证与致谢

- 本项目按 **GPL-3.0-or-later** 分发（完整文本见 [COPYING](COPYING)）。
- 上游代码（proot-me/proot、termux/proot）为 GPL-2.0-or-later：依据其中
  的 "or later" 条款，本作品整体选择按 GPL-3.0-or-later 分发，无需改写
  上游文件中原有的许可头。
- 上游：[termux/proot](https://github.com/termux/proot) 与
  [proot-me/proot](https://github.com/proot-me/proot)——没有它们
  就没有这个项目。
- 思路参考：[gVisor systrap](https://gvisor.dev/docs/architecture_guide/platforms/)
  （RET_TRAP 平台）、闭源 proroot（LD_PRELOAD 路线的可行性证明）。
