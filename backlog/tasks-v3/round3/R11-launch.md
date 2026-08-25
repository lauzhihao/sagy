# R11 launch 观测与提示收尾

先读 `backlog/tasks-v3/round3/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round3/R11`

## 归属文件

- `src/adapters/antigravity/launcher.rs`
- `src/adapters/antigravity/launch_observation.rs`
- `tests/p1_launch_observation.rs`

## R11-1 删除重复的锁等待提示层

第二轮 R1 已经在**加锁层**（`src/core/atomic_io.rs` 的 `lock_exclusive_with_wait_notice` /
`announce_lock_wait_before_blocking`）实现了通用的等待提示，覆盖全部锁点、有全局去重。
而 `launcher.rs:171` 外面还包着第一轮那层 `with_wait_notice`（同样 750ms），
于是 launch 路径在争用时会打印两条不同的提示，并且这一层的 Condvar 实现存在
"通知丢失导致主线程被 join 拖住 750ms"的竞态。

- AC-R11-1.1 删除 `launcher.rs` 里的 `with_wait_notice` 及其调用点和相关单测，
  锁等待提示统一由加锁层负责。
- AC-R11-1.2 删除后，锁争用时仍必须有且只有一条提示（用两个线程/进程争锁的测试证明）。
- AC-R11-1.3 锁立刻可得时，launch 路径不得有任何额外延迟。
- 注意：`src/core/atomic_io.rs` 不在你的归属里，不要改它。

## R11-2 未闭合的 `{` 会把后面真实的 429 一起丢掉（相对基线是回归）

第二轮在 scan 的 Err 分支新增了 `None if !at_eof => { cursor = start; break; }`，
让一个不配对的 `{` 之后的所有 stderr 都滞留在 pending 里直到 EOF。
一旦滞留量越过 `MAX_DIAGNOSTIC_BYTES`，缓冲区被丢弃，后面真实的限流 JSON 一起没了。

- AC-R11-2.1 stderr 形如 "一行含裸 `{` 的日志 + 大量日志 + 一份完整 429 JSON" 时仍须识别限流。
- AC-R11-2.2 不得为此重新打开第二轮修掉的"嵌套对象被当独立证据"的洞
  （`{"m":1,"m":2,"r":{"error":{"code":429,...}}}` 仍必须**不**被判为限流）。
- AC-R11-2.3 两条都要有测试，并对 AC-R11-2.1 做反向验证。

## R11-3 429 优先级高于 401，允许子进程把真实的 401 降级成冷却

`diagnostic_priority` 让 RateLimited > AuthRejected > PermissionDenied，且与出现顺序无关。
一个 token 已失效（401）的 agy 只要额外打一份 canonical 429，就会被记成冷却而不是需要重新登录，
用户看不到"该重新登录"的提示，账号在冷却期后继续被选中、继续失败。

- AC-R11-3.1 同一次运行里同时出现 401 与 429 时，结论必须偏向**更需要用户介入**的那个
  （认证失效优先于限流）。在报告里论证这个方向为什么更安全。
- AC-R11-3.2 只出现 429 时行为不变。
- AC-R11-3.3 反向验证。

## R11-4 被清除但不重建的父进程配置变量

deny-list 遍历后只重建 `GEMINI_API_KEY` / `GOOGLE_APPLICATION_CREDENTIALS` /
`GOOGLE_CLOUD_PROJECT` 三个。原先靠父 shell 导出 `GOOGLE_CLOUD_LOCATION` 指定区域的用户，
升级后会静默丢掉这个配置。

- AC-R11-4.1 区分"认证凭据类"（必须清除，防串号）与"区域/行为配置类"（不该无条件清除）。
  给出你的分类依据。
- AC-R11-4.2 清除仍必须覆盖全部会造成**凭据串号**的变量，AC-R5-4 的测试不得变松。
