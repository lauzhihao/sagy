# tasks-v3 执行者通用规则

所有 T*.md 工单共享以下约束，工单里不再重复。

## 工作方式

1. 你在一个**独立 git worktree** 里工作，与其它 agent 完全隔离。可以自由跑 `cargo`。
2. **只允许修改自己工单"归属文件"一节列出的文件**，外加自己工单指定的**新建**测试文件。
   碰到需要改别人文件才能完成的情况：不要改，在最终报告里写明"需要 X 文件配合"，由验收方处理。
3. 不得修改 `backlog/` 下任何文件（工单和验收脚本对执行者只读）。
4. 不得修改其它工单的测试文件；新增测试只能写进自己工单指定的新文件名。
5. 不新增第三方依赖。确有必要时停下来在报告里说明理由，不要擅自改 `Cargo.toml`。

## 质量门禁（全部必须通过）

```bash
export ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
export GEMINI_HOME=/tmp/sagy-canary
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

两个环境变量**必须**先设置，否则测试会覆盖开发机真实的 Antigravity 凭据（历史缺陷 bugs-001）。

## 工程约束

- Rust 惯用法：小函数、`Result` 传播并带 context、显式类型提升可读性。
- 控制台输出 **ASCII only**，不要 emoji 或特殊 Unicode。
- 代码注释用**中文**解释 *why*（为什么这么改），不解释 *what*。
- 不得硬编码 token、凭据或账号数据。
- 每个 AC 都必须有对应的回归测试，且必须是 **fail-before / pass-after**：
  先确认测试在你改代码之前是失败的，再实现修复。在报告里写明你如何确认了这一点。
- 不得为了让 AC 变绿而放宽既有测试或删除既有断言。若某个既有测试与你的修复语义冲突，
  在报告里单独说明是哪一个、为什么冲突、你怎么改的。

## 最终报告格式

结束时返回结构化结果，必须包含：
- 每条 AC 的实现位置（file:line）与对应测试名
- fail-before 的证据（改之前测试报什么错）
- 你**没有**完成的 AC 及原因
- 你修改和新建的完整文件列表
