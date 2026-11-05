# proto — 无 ptrace 原型（路线 D：LD_PRELOAD 进程内翻译）

这是 nproot 的第一个**无 ptrace** 可运行原型，与闭源 proroot 同思路：
不做事进程外监督，而是把路径翻译搬进 guest 进程内。

**实测状态：glibc（Ubuntu 22.04）与 musl（Alpine 3.24）rootfs 各 7/7
测试通过，全程 TracerPid = 0（零 ptrace）。** 详见下文"实测结果"。

## 原理

```
nproot-lite -r <rootfs> /bin/cat /etc/hostname
        │
        │ 1. 定位 guest 动态加载器（解析 rootfs 内符号链接！）
        │ 2. 设置 NPROOT_ROOT / NPROOT_LOADER / LD_PRELOAD / LD_LIBRARY_PATH
        ▼
exec <rootfs>/lib/ld-*.so.* <rootfs>/bin/cat /etc/hostname
        │
        ▼
┌─────────────── guest 进程 ───────────────┐
│ libnproot.so（LD_PRELOAD 注入）           │
│   open("/etc/hostname")                  │
│     → "<rootfs>/etc/hostname"  ← 进程内翻译，0 次上下文切换
│   execve("/bin/sh")                      │
│     → 解析符号链接/她Bang/PT_INTERP        │
│     → 经 guest loader 重新进入翻译世界     │
└──────────────────────────────────────────┘
```

关键设计（都是踩坑踩出来的，详见下文"已知限制与发现"）：

- **同时挂钩低层包装器与高层入口**（`open*`、`stat*` 与
  `opendir`/`fopen`/`scandir`）：glibc 从 stdio/dirent 内部直连
  `openat(2)`，不走 PLT，但它们作用在我们已翻译的路径上，于是
  `ls`、find、stdio 全部正常；
- **惰性解析 real 函数**：glibc 构造函数按链接图逆序执行，其它对象
  （libselinux！）的构造函数可能先于我们的构造函数调用钩子——
  每个钩子入口都先确保 `dlsym` 解析完成，否则调用空指针；
- **execve 全自行解析**：符号链接链 → shebang → ELF PT_INTERP，
  然后经 guest loader 重新进入（glibc 用 `--argv0` 恢复 argv[0]，
  musl busybox 场景插入 applet 名）；
- **follow 语义钩子做用户态符号链接解析**：rootfs 内的符号链接
  目标是 guest 绝对路径（如 busybox 的 `/bin/cat → /bin/busybox`、
  Ubuntu 的 `/lib64/ld-linux → /lib/ld-linux`），host 内核会按 host
  根解析而 ENOENT，必须用被挂钩的 readlink 在用户态重解。

## 构建

```sh
make                        # libnproot.so + nproot-lite（宿主 libc）
make preload/libnproot-musl.so   # musl shim（需要 musl-gcc，给 Alpine guest）
make android                # aarch64 Android 交叉三件套（需要 zig）
```

launcher 会根据 guest 加载器自动选择 glibc/musl 版 shim。仓库已带
aarch64 Android 预编译产物（`bin/aarch64/`），真机测试无需编译：
见 [`ANDROID.md`](ANDROID.md)。

## 运行

```sh
./launcher/nproot-lite -r <rootfs> [-w <dir>] -- <guest-program> [args...]

# 例（Ubuntu rootfs）：
./launcher/nproot-lite -r ~/rootfs/ubuntu /bin/ls /
./launcher/nproot-lite -r ~/rootfs/ubuntu /bin/sh -c 'cat /etc/os-release'

# 调试：
NPROOT_DEBUG=1 ./launcher/nproot-lite -r ~/rootfs/ubuntu /bin/ls /
```

rootfs 获取（与宿主同架构）：

```sh
# Ubuntu 22.04 (glibc)
curl -O https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04-base-amd64.tar.gz

# Alpine (musl)
curl -O https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/alpine-minirootfs-3.24.3-x86_64.tar.gz
```

## 测试

```sh
ROOTFS=/path/to/rootfs ./run-tests.sh
```

## 实测结果（Linux 5.10 x86_64 沙箱，2026-10-30）

| 测试 | 内容 | Ubuntu 22.04 (glibc) | Alpine 3.24 (musl) |
|---|---|---|---|
| t1 | 隔离：guest `/etc/hostname` 来自 rootfs | PASS | PASS |
| t2 | `ls /` 列出 rootfs 根目录 | PASS | PASS |
| t3 | exec 链：`sh -c 'cat ...'`（execve 重路由）| PASS | PASS |
| t4 | `stat /bin/ls` | PASS | PASS |
| t5 | **无 ptrace**：guest 进程 TracerPid = 0 | PASS | PASS |
| t6 | 对照：ptrace 后端 guest TracerPid ≠ 0 | PASS | PASS |
| t7 | `/etc/os-release` 来自 rootfs | PASS (ubuntu) | PASS (alpine) |

t5/t6 是本原型的核心证据：**同一 rootfs 上，原型运行的 guest 完全
无 tracer；换 ptrace 后端则 TracerPid 立即非零**。

### aarch64 交叉产物（qemu-user 验证，2026-10-31）

`make android` 的产物（静态 musl launcher + glibc/musl shim，
16 KB page 对齐）在 qemu-aarch64 下验证：glibc shim 挂 Ubuntu
22.04 arm64 rootfs 的 `ls`/`cat` 通过；musl shim 挂 Alpine 3.24
arm64 的 `ls` 与 applet 插入 5/5 通过；launcher 对两种 guest 的
shim 自动选择与加载器符号链接解析正确。execve 重路由的最后一跳
（exec guest loader）在 qemu 下无法端到端复现——无 binfmt 时宿主
内核对 aarch64 ELF 返回 ENOEXEC，属模拟器假象；该逻辑已由 x86_64
原生套件覆盖，真机原生执行无此限制。

## 已知限制与发现

1. **静态二进制不可拦截**（路线 D 的本质限制）：guest 内直接 `syscall()`
   的代码、静态链接的 ELF 都绕过 libc 钩子。解药在路线 B/C
   （`docs/BACKENDS.md`）。
2. **glibc 加载器自身不受拦截**：`ld.so` 的缓存/依赖解析靠 launcher
   设置的 `LD_LIBRARY_PATH` 完成，不做路径翻译。
3. **新版 Alpine 的 busybox 已是动态链接**（3.24 实测），musl shim
   + applet 分发即可全量工作；但其它发行版的静态 busybox 仍受限于 1。
4. **musl loader 无 `--argv0`**：musl guest 非 busybox 程序的 argv[0]
   会变成宿主侧路径（busybox applet 场景已正确处理）。
5. **statx 未挂钩**：预加载库定义无版本 `statx` 符号会让引用
   `statx@GLIBC_2.28` 的 BIND_NOW 二进制（Ubuntu 22.04 的
   ls/stat + libselinux）在重定位期崩溃。guest 的 statx 保持未翻译；
   coreutils 在 statx 失效时回退到 fstatat（已翻译）。带版本脚本的定义
   是后续修复方向。
6. **构造函数顺序**（重要工程教训）：glibc 按链接图逆序跑构造函数，
   libselinux 的构造函数先于我们的执行——**所有钩子必须惰性解析
   real 函数**，否则在其它对象的构造期调用就是空指针。
7. 符号链接、shebang、`--argv0`、applet 分发全部在用户态处理，
   这是路线 D 能以 <1000 行 C 跑通两种 libc rootfs 的原因。

## 与终态的差距

本原型验证了"进程内翻译"可行，但它是 libc 级挂钩，不是 syscall 级
监督。终态（路线 B：seccomp RET_TRAP + loader-based exec）见
[`../docs/BACKENDS.md`](../docs/BACKENDS.md) 的路线图。
