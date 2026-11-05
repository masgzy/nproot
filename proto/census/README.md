# Android app-seccomp 普查与强制验证（proto 后端）

真机上 Termux 应用进程被 zygote 装了一个 seccomp 白名单过滤器：白名单外的
syscall 一律 `SECCOMP_RET_TRAP` -> SIGSYS（shell 显示 "Unknown signal 31"）。
这个目录是回答「glibc 容器到底会踩到哪些被禁 syscall」的整套工具，
以及把这些过滤器在 CI 里原样重放、强制验证 proto 后端能活下来的测试。

## 结论速览（2026-11 实测，Debian bookworm arm64 + AOSP 12-16 策略）

对 `bash -l` 登录到提示符的全流程做 syscall 普查（qemu-aarch64 -strace
记录 guest 全部 syscall，再与从 AOSP bionic 源码生成的白名单做差集）：

* 12-16 全版本都禁、且 guest 真会发的只有两项：
  `set_robust_list`（动态加载器启动早期 + libc 初始化 + fork 子进程窗口）
  和 `faccessat2`（bash 探测 /etc/debian_chroot 等）。
* `rseq` 在 glibc 2.36（bookworm）默认不发；更新 glibc（trixie 2.41+）
  会在 `__libc_early_init`（构造函数之前，处理器救不了）和
  pthread_create 的全信号阻塞窗口里发它 —— 两处都无法被 SIGSYS 处理器救。
* `clone3`（glibc 2.39+ 才用）只在 pthread_create/posix_spawn 的
  全信号阻塞窗口里发，同样救不了，必须指令补丁。
* Android 15 起 `clone3`、13 起 `close_range` 进入白名单，这两项的压力
  在新设备上会自然消失。

对应防线（也是本仓库的分工）：

| syscall | 防线 | 位置 |
| --- | --- | --- |
| set_robust_list | 启动器 nop 掉加载器/libc 副本里的 svc 指令 | `src/proto/proto_launch.c` |
| rseq | GLIBC_TUNABLES + libc 副本 nop（双保险） | 同上 |
| clone3 | shim 内存补丁成返回 -ENOSYS | `proto/preload/nproot_preload.c` |
| faccessat2 / openat2 / close_range | shim 的 SIGSYS->ENOSYS 处理器（首个 trap 无条件写 stderr） | 同上 |
| 普查发现「守护也救不了」的项 | 待真机证据加入 shim 指令补丁白名单（放宽匹配规则的补丁在新 glibc 上会误伤随机函数，已回退） | 同上 |
| 设备实测 | `NPROOT_CENSUS=1`（或 PROOT_VERBOSE=2）触发 fork 探针普查：逐号发空参 syscall，区分「被拦但可救」与「守护也救不了」 | 同上 |

syscall 号以内核 UAPI 头为准（x86_64 的 set_robust_list 是 273 不是 272、
rseq 是 334；aarch64 用通用表 99/293）——本项目曾在 x86_64 上栽过想当然
的 272，教训写在这里。

## 文件

* `gen_policy.py` — 从 AOSP bionic 源码（SYSCALLS.TXT + SECCOMP_*.TXT，
  复用 bionic 自带的 genseccomp 解析器）生成各版本 app 策略白名单，
  并映射出 aarch64/x86_64 的 syscall 号。
* `policies/android{12,15}-arm64.txt` — 上面脚本生成的白名单号码表
  （提交进仓库，CI 直接用，避免每次克隆 bionic）。
* `strace_diff.py` — 把 `qemu-aarch64 -strace` 的输出与白名单做差集，
  按时间顺序列出 guest 会踩到的被禁 syscall（本地离线普查用）。
* `ginstall.c` — guest 侧安装器：读白名单、装 seccomp 过滤器
  （strict=裸 TRAP / emul=记录并模拟 ENOSYS / kill=RET_KILL_PROCESS），
  然后 exec 目标命令。注意 qemu-user 不透传 seccomp，所以强制验证
  必须跑在原生 arm64 上（CI 的 arm runner 正合适）。

## 本地普查（x86_64 沙箱）

```sh
# 1. 生成白名单（需要 bionic 源码树和内核 UAPI 头，见脚本头部注释）
python3 proto/census/gen_policy.py
# 2. qemu 记录 guest 全部 syscall
qemu-aarch64-static -strace -L rootfs rootfs/bin/bash -l 2>trace.log
# 3. 差集
python3 proto/census/strace_diff.py trace.log
```

**已知盲区（2026-11-05 实测教训）**：qemu-user 对内核能力的模拟不完整，
凡「探测内核能力成功才发射」的调用，在 qemu 下根本不会发出——
Ubuntu/Debian 的 arm64 动态加载器里都有这样一个 rseq 注册点
（先探测、后调用），qemu 普查显示干净，真内核（真机与 CI 的
arm64 runner）上却会发射并死于构造函数之前。**qemu 普查只能证伪
不能证真**；最终裁决必须靠 CI 的 `android-app-policy` 任务
（原生 arm64 + 真实强制过滤器）。

## CI 强制验证（arm64 原生）

`.github/workflows/tests.yml` 的 `android-app-policy` 任务在原生 arm64
runner 上：用 `ginstall` 装上 android12 白名单（最严基线），先证明裸
bash 会被杀死（过滤器确实咬人），再证明挂着 shim 的 nproot 容器完整
存活——和真机拓扑一致：过滤器包住整个容器，宿主侧二进制不受限。
