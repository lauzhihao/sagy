# sagy Backlog

## 目录结构

```text
backlog/
  README.md          本文件: 协议、分工、当前记分板
  tasks/             第一版工单(叙述式, 面向人)
  tasks-v2/          第二版工单(指令式, 面向低成本执行者) + TEMPLATE.md
  verify/            验收脚本。每个缺陷一个 bugs-NNN.sh, 输出 PASS/FAIL
```

## 分工

- **规格与验收**: 由强模型负责。产出 `tasks-v2/` 工单和 `verify/` 脚本，
  并在执行者报完成后复核 diff。
- **执行与自检**: 由低成本模型负责。只做两件事——按工单改 `src/`，跑 `verify/bugs-NNN.sh`
  直到 PASS。允许多轮迭代，这是成本模型的一部分，不是失败。

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

## 验收脚本约定

- 全部离线可判定：不依赖网络、不依赖真实凭据、不依赖宿主机已装什么。
- 全部在沙箱内运行：`lib.sh` 会把 `HOME`、`SAGY_HOME`、`ANTIGRAVITY_CONFIG_DIR`、
  `GEMINI_HOME` 重定向到临时目录，并注入一个会记录 argv 的假 `agy`。
- 退出码即结论：0 = PASS，1 = FAIL。可直接接进任何自动化循环。

一键跑全部：

```bash
for s in 001 002 003 004 005 006 007 008 009 011 012; do
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

对未提交工作树的验收结果（强模型执行，脚本判定）：

| 编号 | 结果 | 说明 |
| :--- | :--- | :--- |
| 001 cargo test 污染凭据 | PASS | |
| 002 过期 token 阻塞启动 | PASS | |
| 003 model ID 错误 | PASS | |
| 004 凭据文件权限 | **FAIL** | 文件已 0600，但 `accounts/` 目录仍是 0755 |
| 005 429 冷却不可达 | PASS | |
| 006 探测无 TTL | PASS | |
| 007 凭据进 URL | PASS | |
| 008 自更新无校验 | PASS | |
| 009 fs::copy 自拷贝 | PASS | |
| 010 alias 吞子命令 | 阻塞 | 需操作者先定设计意图，见下 |
| 011 SSH host key | PASS | |
| 012 死代码清理 | PASS | |

未完成项已转写为 `tasks-v2/bugs-004a-secure-dir-permissions.md`。

## 待操作者决策

**bugs-010**：`flash list` / `flash update` 目前会被当作 prompt 转发给 agy。
两种设计都自洽，必须先选一个才能写工单：

- A. alias 就是纯启动器，不接受任何 sagy 子命令。
  代价：文档要写清楚，`flash update` 静默不更新会让人困惑。
- B. alias 也能跑 sagy 子命令，按第一个非 flag 参数是否命中 `is_known_subcmd` 分流。
  代价：必须先修 bugs-009 的自拷贝守卫，否则 `flash update` 会把三个别名二进制清零。

选定之前不下发工单。
