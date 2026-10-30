# nproot

<div align="center">

**n**o-**p**trace proot · **neo** proot

一个不依赖 `ptrace(2)` 的 PRoot 替代实现，面向 Android 与 Linux。

[![Tests](https://github.com/masgzy/nproot/actions/workflows/tests.yml/badge.svg)](https://github.com/masgzy/nproot/actions/workflows/tests.yml)
[![nproot CI](https://github.com/masgzy/nproot/actions/workflows/nproot-ci.yml/badge.svg)](https://github.com/masgzy/nproot/actions/workflows/nproot-ci.yml)
[![License: GPL v2+](https://img.shields.io/badge/license-GPL%20v2%2B-blue.svg)](COPYING)
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

### 构建（Android / Termux，NDK）

```sh
# 参考 .github/workflows/nproot-ci.yml 的 android-ndk job：
# NDK clang + 交叉编译 talloc + make CC=...
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
| D. LD_PRELOAD 进程内翻译 | libc 符号插入 + 用户态符号链接/她Bang/exec 解析 | **原型已跑通**（`proto/`）|

完整分析与内核语义发现见 **[docs/BACKENDS.md](docs/BACKENDS.md)**，
探针实测见 **[spike/README.md](spike/README.md)**，
原型实测见 **[proto/README.md](proto/README.md)**。

## 目录结构

```
├── src/            # 核心源码（当前 ptrace 后端 + backend 骨架）
│   └── backend/    # 可插拔后端接口 v0（demo 可独立构建运行）
├── spike/          # 内核机制可行性探针
├── proto/          # 无 ptrace LD_PRELOAD 原型 + 测试
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

- 代码继承 **GPL-2.0-or-later**（见 [COPYING](COPYING)）。
- 上游：[termux/proot](https://github.com/termux/proot) 与
  [proot-me/proot](https://github.com/proot-me/proot)——没有它们
  就没有这个项目。
- 思路参考：[gVisor systrap](https://gvisor.dev/docs/architecture_guide/platforms/)
  （RET_TRAP 平台）、闭源 proroot（LD_PRELOAD 路线的可行性证明）。
