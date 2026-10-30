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
| 兼容基线（现状） | ptrace 后端（保留） |
| 动态链接 rootfs 的日常使用 | **路线 D（proto 已跑通）** |
| Alpine/静态 busybox、彻底 no-ptrace | 路线 B（Phase 2/3 主攻） |
| fake_id0 / deny-paths 等扩展 | 路线 A 直接可用 |
| 老内核（< 5.0）回退 | ptrace 后端 |

分阶段路线图：

- **Phase 0（本次已完成）**：接口骨架 `src/backend/` + 探针 `spike/`
  + 路线 D 原型 `proto/`。
- **Phase 1**：`tracee/event.c` 改造为后端可插拔；ptrace 后端迁入
  `backend_ptrace.c`；新增 `NPROOT_BACKEND` 选择逻辑；unotify 后端
  承载 fake_id0。
- **Phase 2**：路线 D 的二进制补丁模块（libc syscall 桩改写，
  覆盖 glibc 内部直连），目标：Alpine 动态组件全可用。
- **Phase 3**：路线 B 的 loader-based exec（用户态 execve 语义），
  最终退役 exec 边界的 ptrace。

## 5. 后端接口 v0

见 `src/backend/backend.h`。要点：

- `wait_event()/resume()` 描述事件协议；`resume` 三动作：
  `RUN / FAIL(errno) / FAKE_RET(retval)`。
- 能力自述 `backend_caps`：后端必须诚实声明，nproot 启动时按需校验，
  缺能力直接拒绝或降级，绝不静默。
- v0 仅以独立 demo 验证（`make -C src/backend check`，2/2 通过），
  尚未接入主二进制——接入即 Phase 1 的第一件事。

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
