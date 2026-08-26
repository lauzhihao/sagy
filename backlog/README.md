# sagy Backlog

## 当前发布状态

2026-08-24 的全库代码审查（基线 `584ec53`）所列的 P0/P1 —— Repo Sync command injection/路径越界、
checksum fail-open、凭据同步失真、429 自动轮换不可达、state 并发丢更新 —— 均已在
`ec18dfc` 之前关闭，并有代码或回归测试佐证。

2026-08-25 的重构后审计（基线 `ec18dfc`）又发现 3 个 P0、4 个 P1、10 个 P2 和一批 P3。
这些条目**已于 2026-08-25 分四轮全部关闭**，复核提出的 6 个 blocker 与 15 个 major 也已全部修复。

2026-08-26 的发布就绪跟进又关闭了 workflow 中非法提前求值 `runner.temp` 的问题、
authorized-user 缺失 `token_uri` 的真实凭据兼容问题，以及 README/架构与 child auth env
实现不一致的问题。当前本地门禁全绿；代码尚未 push，原生 Windows CI 证据仍待远端产生，
且本轮不创建 tag 或 release。

当前门禁与验收：

```text
cargo fmt --all -- --check                         CLEAN
cargo check --all-targets --locked                 CLEAN
cargo clippy --all-targets --locked -- -D warnings CLEAN
cargo test --all-targets --locked                  22 个 test executable / 485 个测试 / 0 失败
actionlint .github/workflows/*.yml                  CLEAN
backlog/verify/t*.sh                                7 个脚本 / 72 项断言 / 全部 PASS
```

完整的问题基线、修复过程、验收依据、已知残留见：

- [2026-08-26 发布就绪跟进](./reviews/2026-08-26-release-readiness-followup.md)（**当前状态与发布前剩余证据**）
- [2026-08-25 重构后全库审计报告](./reviews/2026-08-25-post-refactor-audit.md)（历史修复与验收结论）
- [2026-08-24 全库代码审查报告](./reviews/2026-08-24-full-code-review.md)（历史，已关闭项的出处）

## 目录结构

```text
backlog/
  README.md          本文件: 协议、分工、当前记分板
  reviews/           跨模块审查报告、发布阻断项与解锁门禁
  tasks/             第一版工单(叙述式, 面向人)
  tasks-v2/          第二版工单(指令式, 面向低成本执行者) + TEMPLATE.md
  tasks-v3/          第三版工单(2026-08-25 四轮修复, 每条 AC 要求 fail-before/pass-after)
                     COMMON.md / T1-T9 / round2 R1-R9 / round3 R10-R12 / round4 R13
  verify/            验收脚本。bugs-NNN.sh 是 tasks-v2 遗留, tNN-*.sh 是当前基线的判据
```

## 分工

- **规格与验收**: 由强模型负责。产出 `tasks-v3/` 工单和验收标准，
  并在执行者报完成后复核 diff。
- **执行与自检**: 由低成本模型负责。只做两件事——按工单改 `src/`，跑工单指定的回归测试
  直到全绿。允许多轮迭代，这是成本模型的一部分，不是失败。

## 执行者铁律

1. `backlog/verify/` 下的文件**只读**。AC 不满足时改的是 `src/`，不是检查脚本。
2. 不得新增或修改 `#[cfg(test)]` 单元测试来让 AC 变绿。
3. 不得改动工单未列出的文件。
4. 跑 `cargo test` / `cargo clippy` 前必须设置这两个环境变量，否则会污染真实凭据：
   ```bash
   export ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
   export GEMINI_HOME=/tmp/sagy-canary
   ```
5. 连续 3 轮自检仍 FAIL 就停下报告，不要继续猜。

## 验收脚本约定（tasks-v2 遗留）

- 全部离线可判定：不依赖网络、不依赖真实凭据、不依赖宿主机已装什么。
- 全部在沙箱内运行：`lib.sh` 会把 `HOME`、`SAGY_HOME`、`ANTIGRAVITY_CONFIG_DIR`、
  `GEMINI_HOME` 重定向到临时目录，并注入一个会记录 argv 的假 `agy`。
- 退出码即结论：0 = PASS，1 = FAIL。可直接接进任何自动化循环。

一键跑全部：

```bash
for s in 001 002 004 005 006 007 008 011 012 013 014 015; do
  printf '%-10s ' "bugs-$s"; bash backlog/verify/bugs-$s.sh >/dev/null 2>&1 \
    && echo PASS || echo FAIL
done
```

## AC 设计规则（写规格的一方遵守）

这几条是踩过坑之后定的，违反其中任何一条都会让执行者陷入无效迭代：

1. **断言可观察行为，不断言内部标识符。**
   写「过期账号仍能启动且 exit 0」，不要写「status 字段等于 `Stale`」——
   执行者猜不到你选的枚举字符串，会为了对齐一个字面量反复空转。
2. **AC 不得比工单更严。**
   工单里允许的逃生口（例如 `--insecure-host-key`），AC 里就不能一刀切禁止。
3. **每条 AC 必须在无网络、无真实凭据的环境下可判定。**
   需要网络的探测路径，用离线可构造的输入去覆盖（例如用固定 `exp` 的 JWT
   走离线分支，而不是打真实 OAuth 接口）。
4. **纯 grep 类 AC 可以被字面满足**，因此必须配人工 diff 复核，不能单独作为通过依据。

## 当前记分板

对四轮修复后代码的实测结果（脚本判定，2026-08-25）：

| 验收脚本 | 覆盖 | 修复前 | 修复后 |
| :--- | :--- | :--- | :--- |
| `t1-state-root.sh` | ROOT-001 / ROOT-002 / 旧权限迁移 | 6/18 | **PASS 18/18** |
| `t2-migration.sh` | MIG-001 v1->v2 迁移逃生阀 | 2/6 | **PASS 6/6** |
| `t4-repo-sync.sh` | SYNC-101 / pool 归一化 / 删除传播 | 4/13 | **PASS 14/14** |
| `t6-offline.sh` | AVAIL-001 探测不可达仍可启动 | 1/5 | **PASS 5/5** |
| `t7-cli.sh` | 死 flag / 真实 help / `-m` 等价 | 5/11 | **PASS 11/11** |
| `t10-sync-commit.sh` | pull 协同提交的坏账号场景 | 5/8 | **PASS 8/8** |
| `t11-first-run.sh` | HOME-002 首次接管既有凭据 | 2/10 | **PASS 10/10** |

`bugs-*.sh`（tasks-v2 遗留）：001 / 004 / 007 / 012 PASS；
002 / 005 / 006 / 008 / 011 / 013 / 014 / 015 FAIL，**全部经核实为脚本自身过期**，
不是代码缺陷。逐条依据见审计报告的「验收依据」一节，要点：

- 013 / 015 把探测端点指向不可达地址后 15/15、7/7 全 PASS —— 线上失败是因为脚本用伪造 JWT，
  真实探测正确地拒绝了它。
- 005 / 006 / 014 断言的 `last_synced_at` 字段在 v2 state 里已不存在；
  `is_in_cooldown` 被当作"应删除的死代码"，但它现在是 `src/core/policy.rs:64` 的活代码。
- 008 / 011 是纯 grep 断言，指向重构前的函数名与代码形状。
- 002 的 fixture 信封已被 AUTH-005 的最小字段校验拒绝。

这些脚本不再作为发布门禁单独采信；**结论以 `reviews/2026-08-25-post-refactor-audit.md`
与 `verify/t*.sh` 为准**。

已退役的验收脚本：

- `bugs-003.sh`（model ID 正确性）——别名删除后由 `bugs-013.sh` 覆盖
- `bugs-009.sh`（fs::copy 自拷贝守卫）——`sync_sibling_binaries` 随别名一并删除，问题消失

## 待执行工单

实现工单已完成。发布前还需要把当前 exact commit 推到 GitHub，取得 Linux quality 与原生
Windows runtime/checksum jobs 的绿色证据；本轮不执行 tag/release。Vertex service-account
文档的 `token_uri` endpoint 信任策略是独立 security review 项，不随 authorized-user
兼容修改扩 scope。其它已知残留仍为 minor，列在两份最新 review 中。

自检命令统一为：

```bash
export ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
export GEMINI_HOME=/tmp/sagy-canary
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
for s in t1-state-root t2-migration t4-repo-sync t6-offline t7-cli t10-sync-commit t11-first-run; do
  printf '%-18s ' "$s"; bash backlog/verify/$s.sh 2>&1 | grep -E '^RESULT'
done
```

## 已决策事项

- **不按模型分入口。** 不做 sclaude 那样的 opus/sonnet 式模型子入口。
  历史上的三个别名二进制已全部删除，只保留 `sagy` 与 `sagy-original`。
- **默认模型固定为 `gemini-3.7-flash-high`。** 需要切换到其它模型时，
  由用户在 agy 交互界面内自行操作，sagy 不介入。
- **sagy 的职责边界**：账号选择与凭据切换，加上一个默认模型。不做模型编排。
