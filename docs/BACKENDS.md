# nproot 无 ptrace 后端设计（BACKENDS.md）

> 状态：**设计稿 v0**（2026-10-30）。本文档是 nproot 去 ptrace 化的总蓝图，
> 配套代码：`spike/`（内核机制探针）与 `src/backend/`（后端接口骨架）。

## 1. 目标与非目标

**目标**

- 在无 root、无 setuid、无 namespace 的 Android/Linux 上，摆脱 proot 对
  `ptrace(2)` 的依赖：消除每syscall 两次上下文切换的开销，同时绕开部分
  厂商内核对 ptrace 的限制。
- 保持 proot 语义的兼容承诺：CLI 参数、`PROOT_*` 环境变量、
  `-r/-R/-S/-b/-0` 等行为不变，`proot-distro` 等生态工具无感迁移。
- ptrace 后端永久保留，作为旧内核与疑难设备的逃生门
  （计划以 `NPROOT_BACKEND=ptrace` 显式选择）。

**非目标**

- 不追求 gVisor 级别的完整安全沙箱；nproot 的出发点是"更快、更兼容的
  proot"，不是安全边界。
- 不在第一版实现跨架构（qemu `-q` 集成）；ptrace 后端继续负责该场景。

## 2. 现状：ptrace 调用点地图

proot 的 ptrace 依赖集中在以下位置（改造时的拆除清单）：

| 位置 | 依赖 |
|---|---|
| `tracee/event.c` | 事件主循环：waitpid + syscall-stop 分发 |
| `tracee/reg.c` | `PTRACE_GETREGS/SETREGS`（寄存器读写）|
| `tracee/mem.c` | `PTRACE_PEEKDATA/POKEDATA` / `process_vm_*`（内存读写）|
| `ptrace/ptrace.c`, `ptrace/user.c`, `ptrace/wait.c` | ptrace 封装层 |
| `syscall/enter.c`, `syscall/exit.c` | 依赖"改寄存器→重放 syscall"的翻译模型 |
| `execve/enter.c` | execve 边界：改写 execve 参数指向 rootfs 内路径 |
| `extension/fake_id0/*` | 伪造 uid/gid 返回值、伪造成功 |

关键观察：**proot 的翻译模型 = "改写 syscall 指针参数 + 重放"**。
任何后端若不能改写参数，就只能"拒绝/伪造返回值"，无法承载路径翻译。
这是全部方案取舍的根源。

## 3. 四条候选路线

### 路线 A：seccomp user-notify（`SECCOMP_RET_USER_NOTIF`）

- 机制：guest 侧安装过滤器 → 指定 syscall 通知监听者进程 → 监听者
  用 `ioctl(NOTIF_SEND)` 回复（放行 / 报错 / 伪造返回值）。
- **实测（`spike/unotify-probe`，Linux 5.10 x86_64）**：
  过滤器安装 ✓；伪造 `getuid()` 返回 4242 ✓；全程零 ptrace ✓。
- 硬约束：**响应结构里没有参数字段**——不能改写指针参数 → 做不了
  proot 式路径翻译；且远程读 guest 内存存在 TOCTOU，需要
  `pidfd_getfd`（5.6+）缓解。
- 适用：fake_id0 类扩展、deny-paths 沙箱、统计审计。
- 内核要求：5.0+（Android 11 上多数设备满足，老设备不可用）。

### 路线 B：seccomp `RET_TRAP` + SIGSYS 处理器 + 自研 execve（终态）

- 机制：过滤器对需拦截的 syscall 返回 `SECCOMP_RET_TRAP` → guest 进程内
  收到 `SIGSYS` → 处理器改写 ucontext（寄存器级，能力等同 ptrace）
  → 直接模拟返回。
- **实测（`spike/trap-probe`，Linux 5.10 x86_64）**：
  1. 处理器内伪造 `getuid()` = 4242 ✓；
  2. **关键语义发现**：信号帧里的 RIP 已指向 syscall 指令**之后**
     （x86_64 入口路径把 RCX 存入 pt_regs->ip），RAX 仍保留系统调用号。
     因此模拟方式是"写返回寄存器、**不要**推进 RIP"——网上流传的
     "跳过 2 字节"适用于 int3/ud2 断点陷阱，不适用于 seccomp 陷阱；
  3. SIGSYS 处理器**不能跨 execve 存活**（execve 放行后新映像首次
     触发陷阱即被 SIGSYS 杀死）✓ 实证。
- 推论：**nproot 必须自己拥有 execve 边界**——用内置 ELF loader
  完成 guest 的每次 execve（proot 的 `src/loader/` 是现成起点，
  但 proot 只用它处理首个进程，路线 B 要求全程使用）。
- 参考实现：gVisor systrap 平台（2023 年起替代 ptrace 成为默认）。
- 代价：clone/vfork/posix_spawn 语义、auxv/AT_EXECFN、
  `/proc/self/exe` 都要补齐，工程量最大，但这是"纯血 no-ptrace"的
  正统形态。

### 路线 C：混合（最务实的 MVP）

- 热路径 syscall 走 seccomp 过滤（放行或伪造返回值）；
- 仅 execve 边界保留 ptrace（`PTRACE_O_TRACEFORK/CLONE/EXEC` 链式跟踪）。
- execve 是低频操作，ptrace 停留成本趋近于零；路径翻译在 exec 边界
  用寄存器改写完成（复用 proot 现有代码）。
- 缺点：严格说仍依赖 ptrace 存在；YAMA/SELinux 对 ptrace 的策略
  仍然适用（Android 上 proot 本来就能用，说明策略可行）。

### 路线 D：LD_PRELOAD + 二进制补丁（proroot 同款，已做原型）

- 机制：不做进程外监督，把路径翻译搬进 guest 进程内——
  `LD_PRELOAD` 挂钩 libc 公共符号；对 glibc 内部直连
  （不走 PLT 的调用），靠挂钩高层入口（`opendir`/`fopen` 等，
  其内部 openat 发生在已翻译的路径上）覆盖。
- 原型见 `proto/`，实测见 `proto/README.md`。
- 优点：零上下文切换、实现量小、立刻可用。
- 硬伤：**静态二进制不可拦截**（Alpine busybox 即是）、guest 内直接
  `syscall()` 的代码不可拦截、`/proc` 语义仿真弱。
- proroot（闭源）额外做二进制补丁（改写 libc 的 syscall 桩）来覆盖
  内部直连调用；nproot 的补丁式方案列为 Phase 2。

## 4. 路线决策

| 场景 | 选型 |
|---|---|
| 兼容基线 | ptrace 后端（保底，`NPROOT_BACKEND=ptrace` 强制） |
| 动态链接 rootfs 的日常使用 | **proto 后端（自 v0.1 起即为默认）** |
| 静态二进制 / qemu `-q` / 非 64 位 | 自动回退 ptrace |
| fake_id0（`-0`） | proto 后端内建 libc 级模拟（NPROOT_FAKEID0） |
| 老内核 / 无 shim | ptrace 后端 |

分阶段路线图：

- **Phase 0（已完成）**：接口骨架 `src/backend/` + 探针 `spike/`
  + 路线 D 原型 `proto/`。
- **Phase 1（已完成，2026-10-31）**：proto 后端接入主二进制
  （`src/proto/proto_launch.c`）并成为**默认后端**；`NPROOT_BACKEND`
  选择逻辑（auto|proto|ptrace）；`-b` 绑定经 `NPROOT_BINDS` 由 shim
  承载；`-0` 经 `NPROOT_FAKEID0` 承载；`/proc` `/dev` `/sys`
  直接共享进 guest；shim 随二进制内嵌（`make EMBED_SHIM=both`）或
  随产物以 `preload/` 目录分发；`-V` 自报后端；启动行自报后端；
  pd 的 `--backend` 开关。unotify 后端承载 fake_id0 的部分由 libc
  级钩子先行替代（见 proto/preload/），`src/backend/` 接口留作
  unotify/trap 的正统接入点。
- **Phase 1.1（已完成，2026-10-31）——glibc/Android 兼容**：Android
  的 app seccomp filter（zygote 装载，`SECCOMP_RET_TRAP`）会把
  glibc 启动期/运行期的若干探测变成 SIGSYS——即 Termux 里的
  "Unknown signal 31"，Debian/Ubuntu guest 因此秒死，musl（Alpine）
  不发这些调用所以幸存。已知触发点：glibc ≥ 2.35 启动期的
  `rseq(2)`、Android 15 策略下的 `set_robust_list(2)`、glibc ≥ 2.34
  的 `clone3(2)`（pthread_create/posix_spawn）、`faccessat2(2)`、
  `close_range(2)` 等。三层修复（`proto/preload/nproot_preload.c`）：
  1. launcher 导出 `GLIBC_TUNABLES=glibc.pthread.rseq=0`，跳过 rseq
     注册（musl 忽略该变量）；
  2. shim 构造函数安装 SIGSYS 处理器（`si_code == SYS_SECCOMP`
     时把返回寄存器改写为 `-ENOSYS`）——seccomp TRAP 不执行
     syscall，handler 可任意仿真返回值，glibc 各探测点对 ENOSYS
     都有回退路径（faccessat2→faccessat、close_range→循环、
     rseq→无）。**局限**：内核经 `force_sig()` 递送 TRAP 信号，
     信号处于阻塞态时 disposition 被重置为 SIG_DFL——glibc 在
     pthread_create/posix_spawn 期间阻塞全部信号，故 clone3 在该
     路径上 handler 救不了（实验验证：裸 clone3 可仿真，
     pthread_create 里的同一个调用不可）；
  3. glibc shim 进程内把 guest libc 的 clone3 指令序列
     （`mov eax,435; syscall`，全库唯一匹配）改写为返回 `-ENOSYS`
     ——glibc 无 clone3 符号可 dlsym（syscall 内联在
     `__clone_internal`），只能按指令模式定位；pthread_create 与
     posix_spawn 随即走 "内核过旧" 回退用 clone(2)。
  回退 ptrace 无法解决此问题（seccomp 先于 ptrace syscall-stop
  执行），必须由 shim 兜底。
  回归用例：`proto/run-tests.sh` t8（clone3-TRAP 过滤器 + 线程化
  glibc guest），CI `tests.yml` 的 "Android seccomp simulation"。
- **Phase 1.1b（2026-11-05，根因闭环）——加载器期 set_robust_list 与
  启动器字节补丁**：上述三层防线齐全后 glibc guest 在真机仍死于
  SIGSYS，根因是 **glibc ≥ 2.35 的动态加载器本体**在启动早期（早于
  preload 重定位、早于 LD_AUDIT 审计初始化、早于任何构造函数与
  ifunc 解析器——均经 ptrace 逐 syscall 实测验证）就发出
  `set_robust_list(2)`，而它在 AOSP 应用策略的 bionic 集合之外
  （`SECCOMP_ALLOWLIST_APP.TXT`），TRAP 必杀且用户态无处挂钩；
  `SIG_IGN` 跨 execve 继承但被 `force_sig()` 重置，自装
  `SECCOMP_RET_USER_NOTIF` 过滤器也无法盖过已有 TRAP（优先级
  TRAP > USER_NOTIF，内核实测）。修复（`src/proto/proto_launch.c`）：
  Android 宿主上自动把 guest 的 `ld.so` 与 `libc.so.6` 副本中该
  syscall 指令（`mov nr; … ; syscall/svc`，仅 PF_X 段、间隙无分支
  才补）nop 掉再执行——调用点返回值本就被忽略（等价于
  pre-2.6.18 内核），rootfs 原文件不动，副本存临时目录，
  `NPROOT_SECCOMP_COMPAT=1|0` 强制开/关。真机预检：Debian 12
  arm64 加载器命中 1 处、libc 命中 2 处。回归：t8b（全危险名单
  过滤器，guest 侧安装——宿主二进制在过滤器外，与 Termux 设备
  拓扑一致）。
- **Phase 1.2（2026-11-03，真机反馈）——外来 libc 二进制原生直执行**：
  Alpine（musl）容器里执行宿主 bionic 工具（pd 默认模式把 Termux
  前缀放进 guest PATH，属上游特性）时，shim 曾把任何带 PT_INTERP
  的 ELF 都重路由给 guest loader → musl 加载 bionic 库 →
  relocation 全崩（缺失 `__register_atfork`、`__errno`、`__sF` 等
  bionic 符号）。修复：shim 解析 PT_INTERP 字符串并按 libc 家族
  守卫（`interp_matches_loader`）——家族一致才走 guest loader；
  不一致（bionic `/system/bin/linker64`、宿主 glibc 等）则剥离
  `LD_PRELOAD`/`LD_LIBRARY_PATH` 后原生直执行，与 ptrace 后端对
  宿主二进制的语义对齐（后续 Phase 1.3 的默认环境隔离让这一层
  只作双保险）。启动横幅同时补充 guest libc 家族
  （`interception backend: proto (no ptrace, guest libc: musl)`）。
  回归用例：`proto/run-tests.sh` t9（外来 libc 直执行）、t10
  （glibc bash 启动）；CI proto e2e 的 Ubuntu bash/apt 与 Alpine
  foreign-binary 断言。
- **Phase 1.3（2026-11-04，真机反馈）——宿主环境默认隔离**：
  真机确认的第二波问题：①guest 继承的 Termux PATH 会穿透——
  Alpine 里敲 `apt` 命中的是宿主 bionic 版（pd 默认把
  `/data/data/com.termux` 绑进容器，宿主二进制可达），musl loader
  对 bionic 库的 relocation 全崩；②继承的 `LD_PRELOAD`/
  `LD_LIBRARY_PATH`/`TMPDIR` 同样指向宿主前缀；③rseq/SIGSYS
  （Phase 1.1）的 `GLIBC_TUNABLES` 修补只在 proto 路径生效，
  ptrace 路径的 glibc guest 同样会踩。修复：新增
  `src/env_sanitize.c`，两个后端统一在启动时（proto 于
  `proto_launch()`、ptrace 于 `launch_process()` 前）清理：
  `PATH` 重置为发行版标准
  （`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`，
  与容器运行时惯例一致，login shell 本就会重建），`TMPDIR` 指向
  Termux 前缀时移除，`LD_PRELOAD`/`LD_LIBRARY_PATH` 剔除 Termux
  前缀条目，`GLIBC_TUNABLES` 补 `glibc.pthread.rseq=0`。仅对
  有独立 rootfs 的会话生效（默认 root `/` 时宿主即 guest，不动）；
  `NPROOT_KEEP_ENV=1` 为逃生门。后端横幅保持 Phase 1.1 的格局：
  proto 会话与 auto-fallback 各自声明，强制 ptrace 的会话不再加
  横幅（输出对比型单测套件整体跑在 ptrace 下，多一行stderr
  就得改全部期望输出）。回归用例：`proto/run-tests.sh` t11
  （guest PATH）、t12（宿主前缀泄漏）、t13（逃生门）。
- **Phase 1.4（2026-11-05，真机仍死引发的普查与补全）**：
  三层防线 + 加载器补丁俱全后真机 Debian 仍偶死于信号 31，遂把
  「Android 应用过滤器到底禁什么」做成可复现的普查：
  `proto/census/`（AOSP bionic 白名单生成器 + qemu -strace 差集 +
  guest 侧过滤器安装器）。普查结论：12-16 全版本都禁且 guest 真会
  发的只有 `set_robust_list` 与 `faccessat2`；`rseq`/`clone3` 的
  致命点在全信号阻塞窗口（handler 被内核 force_sig 重置，救不了）。
  据此：①启动器补丁从单一 set_robust_list 扩成危险清单
  （libc 副本同时 nop rseq，双保险兜住 GLIBC_TUNABLES 失效）；
  ②修正 x86_64 号值（set_robust_list=273 非 272、rseq=334——
  号一律以内核 UAPI 头为准）；③shim 的**首个** seccomp 陷阱现在
  无条件写 stderr（`[nproot] seccomp trap nr=N`），死亡前最后一行
  即凶手号；④`NPROOT_DEBUG` 现在从用户环境透传（此前被环境隔离
  剥掉，`pd sh debian` + NPROOT_DEBUG=1 看不到 shim 日志即此因）；
  ⑤CI 新增 `android-app-policy` 任务：arm64 runner 上用真实
  AOSP 白名单过滤器（android12 最严基线 + android15）包住整个
  容器强制验证存活——qemu-user 不透传 seccomp，只能原生跑。
- **Phase 1.5（2026-11-05）——`--kill-on-exit` 在 proto 后端落地**：
  proto 的 exec 语义没有 tracee 链表可杀，改为监督进程：guest 从
  fork 出的子进程 exec（子进程 setpgid 自成进程组），启动器父进程
  留作 supervisor——PR_SET_CHILD_SUBREAPER 收养孤儿、转发终端信号、
  交接前台进程组；guest 退出后 killpg(SIGHUP→SIGKILL) 清组，
  再扫 /proc 按 ppid 追杀 setsid 逃逸的后代，最后以 guest 的退出
  码退出。真机语义对齐 ptrace 后端的 kill-all-tracees。回归：
  t 系列全绿 + 孤儿/守护进程/pty 交互三场景（CI `android-app-policy`
  任务含孤儿清理断言）。
- **Phase 2（进行中）**：路线 D 的二进制补丁模块（libc syscall 桩
  改写，覆盖 glibc 内部直连），目标：静态 busybox 可拦。
- **Phase 3**：路线 B 的 loader-based exec（用户态 execve 语义），
  最终退役 exec 边界的 ptrace。

## 5. 后端接口 v0

见 `src/backend/backend.h`。要点：

- `wait_event()/resume()` 描述事件协议；`resume` 三动作：
  `RUN / FAIL(errno) / FAKE_RET(retval)`。
- 能力自述 `backend_caps`：后端必须诚实声明，nproot 启动时按需校验，
  缺能力直接拒绝或降级，绝不静默。
- v0 仅以独立 demo 验证（`make -C src/backend check`，2/2 通过）。
  proto 后端的启动路径（exec 语义，非 syscall 监督）暂不经过该
  接口；路线 A/B 落地时经它接入。

## 6. 兼容性承诺

- 所有 `PROOT_*` 环境变量继续有效（drop-in 兼容）；
- 新增变量一律 `NPROOT_*` 前缀（如 `NPROOT_BACKEND`、原型的
  `NPROOT_ROOT`/`NPROOT_LOADER`/`NPROOT_DEBUG`）；
- ptrace 后端永不移除；无法使用新后端时自动回退并打印原因
  （`NPROOT_BACKEND=ptrace` 可强制）。

## 7. 风险清单

| 风险 | 缓解 |
|---|---|
| 各家 Android 内核 seccomp 差异（`PROOT_NO_SECCOMP` 的成因） | spike 矩阵化到多设备；ptrace 回退保底 |
| 路线 B 的 execve 语义长尾（vfork/posix_spawn…） | 先以路线 C/D 服务用户，B 独立分支孵化 |
| 16KB page（Android 15 部分设备）影响 loader 与补丁偏移 | Phase 2 补丁器以符号/模式扫描而非硬编码偏移 |
| unotify TOCTOU | 只做返回值伪造/拒绝，不做远程写 |
