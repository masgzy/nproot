# 参与贡献 nproot

感谢关注 nproot！请先阅读本文件再动手。

## 开发环境

任意 Linux x86_64 / aarch64；Android 上建议 Termux + NDK 或
proot-distro 环境。

```sh
# 依赖
sudo apt install build-essential libtalloc-dev git

# 构建 ptrace 后端
make -C src -j"$(nproc)"

# 运行上游测试套件（需要 busybox-static 等，见 CI 配置）
make -C tests check

# 无 ptrace 相关组件
make -C spike check          # 内核机制探针
make -C src/backend check    # 后端骨架 demo
make -C proto                # LD_PRELOAD 原型
ROOTFS=/path/to/rootfs ./proto/run-tests.sh
```

## 提交规范

沿用上游 AGENTS.md 的约定：

- 标题：`scope: 简述`（如 `backend: add pluggable interception interface`）；
- 正文说明**为什么**改、改了什么、有什么坑，每行 ≤ 72 字符；
- 涉及 AI 辅助的提交加 `Assisted-By: LLM` 脚注；
- 注释、提交信息、PR 描述使用英文；
- **不要**修改 `AGENTS.md`（上游保护策略，改动会被拒绝）；
- 不要把宿主环境的私有路径/用户名/主机名写进提交或文档。

## 改动范围约定

| 目录 | 约定 |
|---|---|
| `src/`（ptrace 核心） | 保持与 termux/proot 的 cherry-pick 友好：重构类改动避免大范围移动代码；品牌化/行为差异集中在独立提交 |
| `src/backend/`、`spike/`、`proto/`、`docs/` | nproot 自有领地，自由演进，但**必须有实测依据** |
| `tests/` | 上游测试不改语义；新增测试放自有目录 |

## 测试要求

- 触碰 `src/` 核心的 PR 必须附 `make -C tests check` 结果；
- 触碰 `proto/` 的 PR 必须附至少一种 rootfs（glibc 或 musl）的
  `run-tests.sh` 输出；
- 声称"无 ptrace"的功能必须包含 TracerPid = 0 的证据
  （`run-tests.sh` 的 t5 已内置）。

## PR 流程

1. Fork → 分支（`feature/xxx`）→ 提交；
2. PR 描述：原始问题 / 影响 / 方案 / 已知代价 / 测试证据；
3. CI 全绿后等待 review。

## 行为准则

尊重上游社区（termux/proot、proot-me）的劳动成果；引用其代码与
文档时遵循其 GPL-2.0-or-later 许可与版权声明。本项目整体按
GPL-3.0-or-later 分发（见 COPYING）；新文件请使用
`SPDX-License-Identifier: GPL-3.0-or-later`。
