# bugs-005 429 冷却降级仍然不可达（退出码只有 8 bit）

- 严重度: P1 (README 主打功能仍未生效)
- 状态: 待修复 (上轮形式上接线，实际不可达)
- 影响面: 多账号轮换的核心价值

## 现象

`src/cli/mod.rs:249` 与 `src/cli/mod.rs:503`:

```rust
if code == 429 {
    adapter.mark_rate_limited(&mut state, &account.id);
}
```

Unix 的进程退出码只保留低 8 位（`WEXITSTATUS`），子进程即使真的以 429 退出，
父进程拿到的也是 `429 & 0xFF = 173`，该条件**永远不成立**。

即使退出码位宽不是问题，agy 本身也不会以 429 退出——限流通常表现为
正常退出码 + stderr/stdout 中的错误文本。

结果：`mark_rate_limited` 依然等价于死代码，ARCHITECTURE.md 第 3 节
描述的"429 -> 5 分钟冷却 -> 自动降级到下一个账号"整条链路没有触发点。

## 修复方案

放弃靠退出码识别，改为输出侧识别。可选路径：

A. 包装子进程输出：把 agy 的 stderr 通过管道转发（同时原样透传到终端），
   扫描 `429`、`RESOURCE_EXHAUSTED`、`rate limit`、`quota` 等关键字，
   命中即调用 `mark_rate_limited`。
   代价：`Stdio::inherit()` 要改成 piped + 转发线程，对交互式 TUI 有风险，
   需要确认 agy 是否依赖 stderr 为 tty（会影响颜色与进度渲染）。

B. 复用探测通道：在 `usage.rs` 的 probe 里已经能拿到 HTTP 429
   （`usage.rs:105-111` 已正确处理），把冷却完全交给探测周期，
   放弃从子进程侧识别。代价是发现延迟到下一次刷新。

C. 折中：保留 B 作为主路径，另外在 `launch_agy` 返回后，
   若退出码非 0，触发一次针对当前账号的即时 probe。

推荐先做 C，成本最低且不动 stdio；A 作为后续增强。

无论选哪条，都要删掉现在这段 `code == 429` 的死条件，避免误导。

## 验收标准

- [ ] 存在一条可实际触发 `mark_rate_limited` 的代码路径，并有沙箱证据
- [ ] 触发后 `sagy list` 显示 `Cooldown (Ns)`，`sagy` 自动切到下一个健康账号
- [ ] 冷却窗口过后自动恢复（`refresh_account_usage` 已有该逻辑，需回归确认）
- [ ] 交互式 TUI 行为不退化（若选 A 方案）

## 依赖

依赖 bugs-002 修复后才能端到端验证"降级到下一个账号"。
