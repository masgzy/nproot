# Android 真机测试指南（无 ptrace 原型）

本指南面向**真实 Android 设备**（aarch64），测试 `proto/` 里的
路线 D 原型：LD_PRELOAD 进程内路径翻译，全程不使用 ptrace。

需要准备：

* 一台 aarch64 Android 真机（`uname -m` 输出 `aarch64`），**无需 root、
  无需解锁**，对内核版本无要求（不需要 seccomp user_notif）；
* [Termux](https://f-droid.org/packages/com.termux/)，请从 F-Droid 或
  GitHub Releases 安装。**不要用 Play 商店版**：它常年不更新，且更高
  targetSdk 下的 W^X 限制可能导致可执行映射失败；
* 能联网（下载 rootfs 用，约 4–30 MB）。

仓库自带预编译 aarch64 产物（`bin/aarch64/`，共约 88 KB，已按 16 KB
page 对齐，4K/16K 页设备通用），真机上**不需要编译任何东西**：

| 文件 | 用途 |
|---|---|
| `bin/aarch64/nproot-lite` | launcher（静态 musl，任何设备可跑） |
| `bin/aarch64/preload/libnproot.so` | glibc shim（Ubuntu/Debian rootfs） |
| `bin/aarch64/preload/libnproot-musl.so` | musl shim（Alpine rootfs） |

## 1. 安装 Termux 并取回原型

```sh
pkg update
pkg install git
git clone https://github.com/masgzy/nproot.git
cd nproot/proto
```

不想装 git 也可以直接下 tarball：

```sh
curl -LO https://github.com/masgzy/nproot/archive/refs/heads/main.tar.gz
tar -xzf main.tar.gz && cd nproot-main/proto
```

## 2. 下载 rootfs（两种 libc 各来一个）

```sh
mkdir -p ~/rootfs/alpine ~/rootfs/ubuntu

# Alpine 3.24（musl，~4 MB）
curl -L -o /tmp/alpine.tgz \
  https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/aarch64/alpine-minirootfs-3.24.3-aarch64.tar.gz
tar -xzf /tmp/alpine.tgz -C ~/rootfs/alpine

# Ubuntu 22.04（glibc，~27 MB）
curl -L -o /tmp/ubuntu.tgz \
  https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04-base-arm64.tar.gz
tar -xzf /tmp/ubuntu.tgz -C ~/rootfs/ubuntu
```

rootfs 放在 Termux 家目录即可，不要放在共享存储（`/sdcard` 挂载了
noexec，且权限位不可靠）。

## 3. 跑起来

```sh
LITE=$PWD/bin/aarch64/nproot-lite

# Alpine（musl）
$LITE -r ~/rootfs/alpine /bin/ls /
$LITE -r ~/rootfs/alpine /bin/sh -c 'cat /etc/os-release; uname -m'

# Ubuntu（glibc）
$LITE -r ~/rootfs/ubuntu /bin/ls /
$LITE -r ~/rootfs/ubuntu /bin/sh -c 'cat /etc/os-release'

# 直接进一个 guest shell
$LITE -r ~/rootfs/ubuntu /bin/bash
```

预期输出：`ls /` 列出的是 **rootfs** 的根目录（`bin dev etc ... usr`，
而不是 Android 的根），`os-release` 是 rootfs 自己的，`uname -m`
输出 `aarch64`。

launcher 会自动探测 guest 的动态加载器并选择对应 libc 家族的 shim
（musl guest 用 `libnproot-musl.so`，glibc guest 用 `libnproot.so`）。

## 4. 测试套件（t1–t10）

```sh
ROOTFS=~/rootfs/alpine LITE=$PWD/bin/aarch64/nproot-lite ./run-tests.sh
ROOTFS=~/rootfs/ubuntu LITE=$PWD/bin/aarch64/nproot-lite ./run-tests.sh
```

预期：t1–t5、t7、t9（外来 libc 二进制原生直执行）全 PASS；t8
（Android seccomp 模拟）与 t10（glibc bash 启动）只在有 cc 和
ubuntu rootfs 时运行。t6 是
"ptrace 后端对照"（同一 rootfs 上 TracerPid ≠ 0），需要 ptrace 后端
的 aarch64 二进制，可选两种方式：

```sh
# 方式 A：Termux 里直接编译 ptrace 后端
# 静态链 talloc（推荐，产物自包含）：Termux 的 libtalloc 包自带
# $PREFIX/lib/libtalloc.a（≥2.5.0）
pkg install clang make libtalloc
make -C ../src -j"$(nproc)" \
  CPPFLAGS="-D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I../src -I$PREFIX/include" \
  TALLOC_LINK="-l:libtalloc.a"
ROOTFS=~/rootfs/ubuntu LITE=$PWD/bin/aarch64/nproot-lite \
  PTRACE_NPROOT=$PWD/../src/nproot ./run-tests.sh

# 方式 A'：若要把 talloc 留在动态库（与 Termux 的 proot 包一样），
# 去掉 TALLOC_LINK 即可，运行时同样依赖 pkg install libtalloc 装进
# $PREFIX/lib 的 libtalloc.so.2

# 方式 B：从 CI 下载（GitHub Actions → nproot CI → android (aarch64,
# bionic) job 的 artifact nproot-android-arm64，需要 GitHub 登录）。
# 产物已把 talloc 静态链接进二进制，解压即用，无需任何额外依赖；
# 静态化之前的旧产物才需要配套的 libtalloc.so.2
```

## 5. "无 ptrace" 的直接证据

一条命令即可证明（guest 自己报告自己的 TracerPid）：

```sh
$LITE -r ~/rootfs/ubuntu /bin/sh -c 'grep TracerPid /proc/self/status'
# TracerPid: 0        ← 没有任何 tracer

# 对照：ptrace 后端下同样的命令输出非 0（即 t6）
../src/nproot -r ~/rootfs/ubuntu -b /proc /bin/sh -c 'grep TracerPid /proc/self/status'
```

也可以从宿主侧验证：先在后台起一个长驻 guest 进程，再看它的
`/proc/<pid>/status`：

```sh
$LITE -r ~/rootfs/ubuntu /bin/sleep 300 &
sleep 1 && grep TracerPid /proc/$!/status   # → TracerPid: 0
```

注意：Termux 里 `strace -p <guest_pid>` 是**可以** attach 成功的
（同 uid、yama ptrace_scope=0），attach 之后 TracerPid 会变成 strace
的 pid——那是我们自己附加上去的，不是原型在 trace。判据始终是
**不附加时 TracerPid = 0**。

## 6. 性能

路线 D 的路径翻译发生在 guest 进程内（0 次上下文切换），ptrace 后端
每个系统调用都要停陷两次。粗略对比：

```sh
time $LITE -r ~/rootfs/ubuntu /bin/true        # 原型
time ../src/nproot -r ~/rootfs/ubuntu /bin/true # ptrace 后端（若已编译）
```

启动类短命令上差距最明显；纯 CPU 计算差距不大。

## 7. 排障与 Android 特有事项

* **`CANNOT LINK EXECUTABLE ... library "libtalloc.so.2" not found`**
  → 用的是静态化之前的旧 CI 产物。新的自包含产物已把 talloc 静态链
  进二进制且 loader 也内嵌（单文件），重新下载即可。
* **`can't create temporary directory: Permission denied` / `can't
  create glue rootfs`** → 临时目录不可用。nproot 只认 `PROOT_TMP_DIR`
  和 `/tmp`（Android 上没有 `/tmp`）：设置了 `PROOT_TMP_DIR` 时它必须
  可写，否则直接报错；未设置时新产物会自动回退到 `$PREFIX/tmp`。
  手动指定：`export PROOT_TMP_DIR=$PREFIX/tmp`。另外**不要在
  /sdcard 下跑**（FUSE 挂载，创建/重命名语义受限，提取出来的
  loader 也会因 noexec 无法执行），换到 Termux 家目录再试。
* **`ls /` 列出的是 Android 根目录** → 没走到翻译逻辑，检查 `-r` 是否
  指向解压好的 rootfs（launcher 内部会 realpath，相对路径也行）。
* **`Exec format error`** → rootfs 架构与设备不符（比如下了 x86_64 的
  rootfs）。真机必须是 `aarch64` 后缀的包。
* **Termux 版本不对**（Play 商店版）→ 表现为 exec/mprotect 报错或
  `Permission denied`，换 F-Droid/GitHub 版。
* **静态链接的 guest 二进制拦不到**：路线 D 的本质限制（钩子挂在
  libc 的 PLT 上，静态 ELF 没有这一层）。Alpine 3.24 的 busybox 是
  动态链接，不受影响；个别发行版的静态 busybox 需要等路线 B/C
  （见 `../docs/BACKENDS.md`）。
* **glibc guest（Debian/Ubuntu）启动即死 "Unknown signal 31"**：
  已修复（2026-11-05，根因定位 + 三层防线 + 启动器补丁）。真正的
  死因链条：Android 应用 seccomp 策略对 bionic 之外的 syscall 一律
  `SECCOMP_RET_TRAP`；glibc ≥ 2.35 的**动态加载器本体**在重定位完
  preload 之前、任何构造函数之前就会调用 `set_robust_list(2)` ——
  此时 shim 的 SIGSYS handler 尚未武装（实测：preload 构造函数、
  LD_AUDIT 审计模块、ifunc 解析器全都晚于它），进程直接死于内核
  默认动作。其余致命探测点的兜底：`rseq`（GLIBC_TUNABLES 禁用 +
  libc 副本指令 nop，后者兜住 pthread_create 全信号阻塞窗口这种
  handler 救不了的场合）、`clone3`（shim 指令补丁）、
  `close_range`/`openat2`/`faccessat2`（shim 的 SIGSYS→ENOSYS
  handler）。启动器的最终防线：在 Android 宿主上自动把 guest 的
  `ld.so` 与 `libc.so.6` **副本**中的危险 syscall 指令补丁掉再执行
  （rootfs 原文件不动，副本放临时目录；`NPROOT_SECCOMP_COMPAT=1`
  可强制开启、`=0` 强制关闭，非 Android 宿主默认不启用）。
  白名单普查方法论与各版本策略差异见 `census/README.md`。
  若个别 guest 仍死：**首个** seccomp 陷阱现在**无需调试开关**就会
  打到 stderr（`[nproot] seccomp trap nr=N`），`NPROOT_DEBUG=1`
  （现已支持从用户环境透传进容器）则每个陷阱都带
  `-> ENOSYS` 后缀；死亡前最后一行就是凶手号，据此可定位。
  紧急逃生门：`NPROOT_BACKEND=ptrace`。
  **注意**：`bin/aarch64/nproot-lite` 是独立的精简启动器，**不含**
  该启动器补丁——真机上跑 glibc 发行版请使用 CI 产物的 `nproot`
  主程序（pd 默认调用的就是它）；nproot-lite 仅用于仓库内
  原型自测（musl guest 无此问题）。
* **guest 内执行宿主二进制（如 pd 默认模式把 Termux 前缀放进
  PATH）**：shim 按 PT_INTERP 的 libc 家族守卫——同家族才经 guest
  loader 重路由，异家族（bionic、宿主 glibc）原生直执行，与
  ptrace 后端行为一致；此前表现为 guest loader relocation 全崩，
  已修复。
* **`LD_PRELOAD` 被 launcher 覆盖**：设计如此，guest 内只注入本原型
  的 shim；Termux 自带的 termux-exec 不受影响（它在 Android 侧，
  不会进入 guest）。
* **`/proc`、`/dev`、`/sys` 未翻译**：原型直接放行到宿主（Android 的
  `/proc` 对 guest 足够用），这是已知简化，见 `README.md` 的
  "已知限制"。
* **glibc guest 里 `apt` 报 fchmodat 相关错误**：老 bug，上游 proot
  5.5.0 已在 ptrace 后端修过；原型尚未覆盖 fchmodat2，属预期。
* **32 位设备**（armeabi-v7a）：当前预编译产物只有 aarch64。

## 8. 从源码重建 aarch64 产物（可选）

任意有 [zig](https://ziglang.org/download/) 的机器（含 Termux：
`pkg install zig`）：

```sh
cd proto && make android ZIG=zig   # 生成 bin/aarch64/ 三件套
```

x86_64 宿主上验证源码逻辑（非交叉，跑 `run-tests.sh` 全套）见
`README.md` 的"构建/测试"两节；交叉产物在 qemu-user 下的验证结果
记录在 `README.md` 的"实测结果"。

## 9. 独立 seccomp 普查（不进容器，直接量出过滤器全貌）

`proto/census/host_census.c` 编译出一个**静态**可执行文件
（`make android` 产 `bin/<arch>/host-census`，CI 的
`nproot-android-arm64` artifact 里也带了），放到任何 Android 进程里
直接跑，即可量出本进程从 zygote 继承的过滤器全貌——哪些 syscall 被
拦、动作是可捕获的 TRAP 还是无法捕获的 KILL：

```sh
./host-census
```

输出三行：

* `[nproot] census: kernel ...` —— 内核与架构；
* `[nproot] census: filter blocks N: ...` —— 被拦的 syscall 号全表；
* `[nproot] census: guard cannot save N: ...` —— 其中连
  SIGSYS→ENOSYS handler 都救不回来的（即 RET_KILL 系列），这些就是
  「静默死亡」类问题的元凶：handler 根本收不到 SIGSYS。

判定方法：某 syscall 出现在 *blocks* 但不在 *guard cannot save* →
TRAP/ERRNO，shim 能兜住；出现在 *guard cannot save* → 必须靠指令
补丁（启动器 L0）或改用旧 syscall 号避开。把结果贴回仓库即可定位
guest 死亡时的最后一个 syscall。

为什么是独立静态程序而不是预载 shim：Android linker 的命名空间只
放行应用自身库目录里的 LD_PRELOAD；shim 的 glibc 变体带
DT_NEEDED libc.so.6（bionic 无此库）；musl 变体又依赖 bionic 没有
的 `__errno_location`。静态二进制绕开全部三类坑。

注意：普查会对 0..463 每个号 fork 一个一次性探测进程（约九百个，
~10 秒）。把结果贴回仓库时请注明设备型号与 Android 版本。

## 10. seccomp 盾牌：census 驱动的存根硬化（SHIELD）

真机上还出现过比「加载器早期陷阱」更隐蔽的死法：**census 全绿、
shim handler 正常、guest 却在启动若干秒后静默死于信号 31**（退出码
159）。根因是内核语义：`force_sig()` 在**信号被屏蔽**投递 seccomp
TRAP 时会把处置重置为 `SIG_DFL` —— 而 glibc 在
`fork`/`posix_spawn`/`pthread_create` 周围阻塞**全部**信号。任何
被禁 syscall 在这类「全信号阻塞窗口」里发出，进程必死，且 handler
一行日志都不会有（AVD 上连 python 的 `subprocess` 都会这样死，
bionic 的 fork 同理）。另据实测，内核对多过滤器取**动作值最小者**：
`TRAP(0x0003)` 永远压过自装过滤器的 `ERRNO(0x0005)`，所以
「自装 ERRNO 过滤器抢先返回 ENOSYS」这条路在内核层面就走不通。

上述语义已在设备内核源码里逐行验证（某 GKI 6.1 arm64 设备，
`6.1.145-android14-11`，Android 16 用户态）：TRAP 路径为
`force_sig_seccomp(this_syscall, data, false)` →
`force_sig_info_to_task(..., HANDLER_CURRENT)`，其中
`blocked = sigismember(&t->blocked, sig)`，一旦
`blocked || ignored` 就把 `sa_handler` 重置为 `SIG_DFL` 并解除屏蔽
——重置发生在**投递之前**，handler 原理上永远看不到屏蔽窗口内的
TRAP。该文件与 android14-6.1 分支头逐字节对比：seccomp.c 仅差
notify 等待状态机（快照较旧），signal.c 路径上唯一厂商钩子
`android_vh_signal_coredump_check` 只影响 coredump 决策；系统调用
号表为原生 asm-generic（6.1 无 fchmodat2，452 号是保留洞、照样
TRAP）。结论：无厂商魔改，盾牌（让 guest 发不出被禁号）是唯一
完备修法。

盾牌因此走指令补丁路线（与启动器 L0 同理，但 census 驱动、精确到
被禁号）：shim 构造函数扫描**所有已加载对象的代码段**，把
`movz x8, #NR; svc #0`（aarch64）/ `mov eax, NR; syscall`（x86_64）
中 **NR 属于 census 被禁名单**的存根就地补成「置 -ENOSYS 返回值 +
nop 掉 svc/syscall」——原始的错误处理代码（cmp/jae/ret）原样保留，
故补丁后语义与 guard 的 ENOSYS 模拟完全一致；连 KILL 类动作一起
免疫。`movz x8,#NR; svc #0` 这个 8 字节对本身就是在发起 NR 号
syscall，不存在误匹配。

* 普查结果按内核版本缓存在 `PROOT_TMP_DIR/nproot-seccomp-v1-<release>`，
  只有首次启动付约几秒的 sweep 成本，之后每次启动只做一次毫秒级扫描；
* aarch64 匹配掩码必须**带上 Rd 位**：完整模式是 `0xD2800008`（movz
  **x8**），首版把 Rd 写进掩码、常数却按 `0xD2800000`（x0）比较——所有
  x8 存根被静默拒绝，真机一度「hardened 0」照旧死于信号 31，而
  x86_64/CI 全绿（B8 操作码无寄存器位，掩盖了回归）。教训：预处理门控
  的单架构分支不被对方架构的 CI 编译，汇总行必须能自证；
* 汇总行因此带 `scanned N exec mappings`（实际扫描过的可执行映射数，
  census 模式与缓存路径都有）：`hardened 0` 但 scanned 正常 → 匹配器
  出了问题；`scanned 0` → maps 解析出了问题。debug 级别下逐存根打
  `patched nr=…`，mprotect 失败不计入硬化数也不再静默；
* `NPROOT_SHIELD=0` 关闭；`NPROOT_SHIELD=1` 在非 Android 内核上强制
  开启（CI 自测用）；显式 `NPROOT_CENSUS=1` 时先 verbose 普查再硬化；
* census 的 sweep 现跑在可重启的一次性 sweep 子进程里（raw
  clone，不走 libc fork），sweep 子进程被 SIGSYS 打死也会从断点续跑
  —— hostile 过滤器无法让普查失声，重启消息本身还能定位
  「父进程上下文死亡」发生的 syscall 号；
* handler 日志里的 syscall 号已修正为正序（旧构建把 224 打成
  "422"，比对 census 名单时倒序即真相）。

合成过滤器复现实验（`census/filter_parent.c` + `census/stub_probe.c`，
CI 的 tests 工作流含此步骤）：TRAP(110)+KILL(105)+全信号阻塞窗口，
无 shim 必死（159），带 shim 存活且 `getppid()->-38`（与 guard 会
模拟的值一字不差）。
