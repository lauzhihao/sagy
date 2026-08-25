# R5 launch 观测与终端复核回归

先读 `backlog/tasks-v3/round2/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round2/R5`

## 归属文件

- `src/adapters/antigravity/launcher.rs`
- `src/adapters/antigravity/launch_observation.rs`
- `tests/p1_launch_observation.rs`
- `tests/p1_launcher_auth_env.rs`

## R5-1（BLOCKER）子进程可以伪造 429

`scan()` 在候选文档解析失败时只把游标前进 1 字节：

```rust
Err(error) => {
    self.record(error);
    cursor = start.saturating_add(1);
}
```

而 Ok 分支会整文档跳过（注释明确写了"不把它的嵌套对象重新当成独立证据"）。
于是一个被 duplicate-key / 非法转义 / 超深嵌套拒绝的**外层**文档，
它的**内层**对象会被当成独立证据重新扫描。PoC（子进程 stderr，exit 1）：

```
{"m":1,"m":2,"r":{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}}
```

外层因重复键 Err -> cursor=start+1 -> 命中内层 -> 判为 canonical 429 ->
落 cooldown 并触发换号。ec18dfc 建立的"只接受完整、无重复键文档"不变量在错误路径上被静默放弃。
（执行者自己写的守卫测试用的是 `{"outer":{"error":...}}`，那是 Ok 分支，恰好绕开了真正的洞。）

- AC-R5-1.1 上面这条 PoC 输入必须**不**被判为 RateLimited。
- AC-R5-1.2 解析失败时游标必须跳过整个候选文档的范围，而不是前进 1 字节。
  说明你如何界定"整个候选文档"的边界（错误位置、括号配对、还是别的）。
- AC-R5-1.3 合法场景不得回归：日志行 + 一份完整 429 JSON + 日志行仍须识别；
  chunk 边界切在多字节 UTF-8 字符中间仍须识别。
- AC-R5-1.4 反向验证：把游标改回 +1，AC-R5-1.1 的测试必须变红。

## R5-2（MAJOR）with_wait_notice 存在 lost wakeup，每次 launch 可能空转 750ms

watcher 线程在 `wait_timeout` 之前不检查完成标志。`work()` 在 watcher 被调度到之前完成时
`notify_all` 丢失，watcher 睡满 `LOCK_WAIT_NOTICE_DELAY`，主线程在 `join` 上一起阻塞。
生产侧 work = 三次 flock + stat，量级 ~1ms，与线程调度延迟同量级，机器有负载时必然中招。
现有单测第一段 work 是 `|| 7_u32` 瞬时返回，会实打实空转 500ms 才通过，测试只断言"安静"，把缺陷完全掩盖。

- AC-R5-2.1 work 立即返回时，整个包装的额外耗时必须可忽略（给出一个有上界的断言）。
- AC-R5-2.2 仍然不得在锁立刻可得时打印提示。
- 注意：R1 正在**加锁层**实现通用的等待提示。合并后如果两层都打印，验收方会删掉你这一层。
  你只需要保证自己这层没有竞态；不要为此改动 R1 归属的文件。

## R5-3（MAJOR）父进程 stderr 不可写仍然 panic

AC 原文点名的 `sagy ... 2>&1 | head -c 0` 场景现在退出 101（panic）而不是子进程退出码。

- AC-R5-3.1 该场景必须返回 agy 子进程的真实退出码。
- AC-R5-3.2 该场景下已解析出的限流诊断不得丢失。
- AC-R5-3.3 测试必须真的构造不可写的 stderr（关闭的 fd 或提前退出的管道读端），
  不能只调用内部函数。

## R5-4（MAJOR）接线 Google 认证环境变量 deny-list

`src/core/credential.rs` 里有一张 `GOOGLE_AUTH_ENV_VARS` 表（R2 负责保证内容与可见性），
但 `launcher.rs` 仍然只 `env_remove` 三个硬编码变量：
`GEMINI_API_KEY` / `GOOGLE_APPLICATION_CREDENTIALS` / `GOOGLE_CLOUD_PROJECT`。

- AC-R5-4.1 launcher 必须遍历那张表清理**全部**变量，再按当前账号类型重建需要的那几个。
- AC-R5-4.2 扩展 `tests/p1_launcher_auth_env.rs`：父进程设置 `GOOGLE_API_KEY`、
  `GOOGLE_GENAI_USE_VERTEXAI`、`GOOGLE_CLOUD_LOCATION` 后启动，断言子进程看不到它们。
- AC-R5-4.3 反向验证：把遍历改回三个硬编码变量，该测试必须变红。

## R5-5（MINOR）

- AC-R5-5.1 扫描式解析把 401/403 的识别面一并放宽到"日志行内嵌 JSON"，且"首个 canonical 文档获胜"。
  真实的"先 401 后 429"序列会被记成需要重新登录而不是冷却。定义并测试一个明确的优先级规则。
- AC-R5-5.2 AC-2.2（TTY 下仍能观测 429）走了兜底条款。在报告里补上取舍论证：
  为什么不用 PTY、代价是什么、以后要改需要动什么。这一条只要求文字，不要求实现。
