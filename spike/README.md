# spike — 无 ptrace 后端可行性探针

两个独立的 C 程序，用于在目标内核上验证 nproot 去 ptrace 化所依赖的
内核机制。**所有结论均为沙箱实测**（Linux 5.10 x86_64），不是推测。
设计讨论见 [`../docs/BACKENDS.md`](../docs/BACKENDS.md)。

## 构建与运行

```sh
make          # 编译两个探针
make check    # 运行并汇总（2/2 通过 = 该内核两条路线都可行）
```

## 探针 1：`unotify-probe`（seccomp user-notify 路线）

验证 `SECCOMP_RET_USER_NOTIF`（Linux ≥ 5.0）：

1. 非特权安装带 `SECCOMP_FILTER_FLAG_NEW_LISTENER` 的过滤器；
2. 子进程的 `getuid()` 被监听者拦截，**伪造返回值 4242**；
3. 全程零 ptrace。

实测输出（节选）：

```
[1] OK   user-notify filter installed, listener fd = 3
[child] real uid = 1001, now calling getuid()
[supervisor] notification: syscall 102 from pid 2929, args = [...]
[supervisor] forged return value 4242
[2] OK   return-value injection works, zero ptrace involved
RESULT: unotify usable on this kernel
```

**结论**：unotify 可以承载 fake_id0 类扩展（伪造返回值）与拒绝式沙箱，
但响应结构**没有参数字段**——proot 式路径翻译（改写指针参数）无法通过
它实现。

## 探针 2：`trap-probe`（seccomp RET_TRAP / SIGSYS 路线）

验证 gVisor systrap 同款的进程内拦截：

1. 过滤器对 `getuid` 返回 `SECCOMP_RET_TRAP` → SIGSYS 处理器改写
   ucontext，**寄存器级伪造返回值 4242**；
2. 过滤器对 `openat` 也设陷阱：子进程 exec 后（execve 放行），新映像的
   动态加载器第一次 `openat` 即触发 SIGSYS 且无处理器 → 死亡。

实测输出（节选）：

```
[1] OK   in-process emulation works: getuid() = 4242, ... no ptrace
[2] OK   execve resets the SIGSYS handler: child killed by SIGSYS after exec
RESULT: trap route viable, but execve boundary must be owned by nproot
```

### 实测发现的内核语义（重要）

SIGSYS 信号帧里保存的 RIP **已经指向 syscall 指令之后**
（x86_64 系统调用入口把用户返回地址从 RCX 存入 pt_regs->ip），RAX
仍保留系统调用号。因此模拟方式是"**写返回寄存器、不要推进 RIP**"。
网上流传的"跳过 2 字节"适用于 int3/ud2 断点陷阱，**不适用于
seccomp 陷阱**。这一条已写进探针注释和 `docs/BACKENDS.md`。

调试时可用 `NPROOT_SPIKE_DEBUG=1 ./trap-probe` 查看信号帧细节。

## 对后端选型的意义

| 探针结论 | 影响 |
|---|---|
| unotify 可用、只能伪造返回值 | 路线 A 承载 fake_id0 / deny-paths |
| TRAP 可寄存器级模拟 | 路线 B 是"纯血 no-ptrace"的正统形态 |
| SIGSYS 处理器不能跨 execve | 路线 B 必须自研 execve（loader-based exec）|
| `--argv0` / applet / 链接解析等启动语义 | 已在路线 D 原型（`../proto/`）中落地验证 |
