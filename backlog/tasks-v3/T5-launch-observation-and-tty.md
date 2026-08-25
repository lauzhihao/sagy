# T5 429 观测的可达性与终端行为（P2）

先读 `backlog/tasks-v3/COMMON.md`。
背景见审计报告的 OBS-001、TTY-001，以及 P3 的 `-m` 识别、父进程 stderr 写失败、LOCK-001 的 launcher 一侧。

## 归属文件（只能改这些）

- `src/adapters/antigravity/launcher.rs`
- `src/adapters/antigravity/launch_observation.rs`
- 新建：`tests/p1_launch_observation.rs`

## AC-1（P2）429 观测必须对真实 agy 输出可达

现状：观测器对**整个 stderr buffer** 做一次严格 JSON 解析（`deserializer.end()` 不容忍尾随内容），
因此 agy 只要在限流 JSON 之前或之后多打一行日志，诊断就退化成 `None`，冷却与自动降级全部不触发。

- AC-1.1 stderr 内容为"若干行普通日志 + 一行 Google 风格的 429 JSON + 若干行普通日志"时，
  必须识别为限流并进入冷却、在同一次调用内降级到下一个账号。
- AC-1.2 stderr 中限流 JSON 被拆散在多个 chunk 边界上（包括拆在多字节 UTF-8 字符中间）时，仍必须识别。
- AC-1.3 stderr 输出超过缓冲上限时，不得因为早期的无关日志把后面的限流 JSON 挤掉——
  说明你选择的策略（例如按行/按对象扫描而不是整块解析）并给出上限行为的测试。
- AC-1.4 非限流的普通失败（例如认证错误 JSON、纯文本 panic）不得被误判为限流。
- AC-1.5 现有的端到端测试 `tests/p1_rate_limit_fallback.rs` 必须继续通过（不得修改该文件）。

## AC-2（P2）不得破坏 agy 的终端行为

现状：`stderr(Stdio::piped())` 是无条件的，agy 子进程的 `isatty(2)` 恒为 false，
这是相对 `584ec53` 的回归（那时是 `Stdio::inherit()`）。

- AC-2.1 sagy 自身的 stderr 是 TTY 时，agy 子进程看到的 stderr 也必须是 TTY。
- AC-2.2 在满足 AC-2.1 的前提下，429 观测仍必须工作（说明你的方案：例如 PTY、
  或非 TTY 时才管道化、或改从其它可靠信号获取诊断；方案必须在报告里论证清楚取舍）。
- AC-2.3 若你的方案在 TTY 场景下确实无法观测 429，必须：默认保证终端行为不退化，
  并在报告里明确写出"TTY 场景下 429 观测退化为下一次启动时的 probe 发现"。
  不允许为了观测而默认牺牲交互体验。
- AC-2.4 转发路径不得改变 agy 输出的字节内容与顺序。

## AC-3（P3）父进程 stderr 写失败不得吞掉子进程结果

- AC-3.1 sagy 自己的 stderr 不可写（例如 `sagy ... 2>&1 | head -c 0`、fd 已关闭）时，
  返回值必须仍是 agy 子进程的真实退出码。
- AC-3.2 该场景下已经解析出的限流诊断不得丢失（冷却仍须落库）。

## AC-4（P3）`-m` 必须与 `--model` 等价

- AC-4.1 `sagy -m custom-model` 传给 agy 的 argv 里不得再出现注入的默认 `--model`。
- AC-4.2 `--model=custom`、`--model custom`、`-m custom`、`-m=custom` 四种写法行为一致。
- AC-4.3 用户未指定模型时，默认模型注入行为不变。

## AC-5（P2）锁等待必须可诊断

launch 期间持有 credential lock 与 active-home lock，且全部是无超时的 `lock_exclusive`。

- AC-5.1 另一个 sagy 进程正在 launch 时，第二个 sagy 命令不得静默挂起：
  必须在可接受的时间内输出一条 ASCII 提示，说明正在等待另一个 sagy 会话。
- AC-5.2 你只能改自己归属文件里的加锁调用点。若必须修改 `atomic_io.rs` / `atomic_store.rs`
  才能表达"带提示的等待"，不要改那两个文件，在报告里写明需要的接口签名，由验收方协调。

## 自检

除通用门禁外，AC-1.1 与 AC-2.1 必须给出可复现的实验记录（fake agy 脚本 + 实际观测结果）。
