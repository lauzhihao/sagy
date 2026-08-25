# R12 收尾清理

先读 `backlog/tasks-v3/round3/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round3/R12`

## 归属文件

- `src/adapters/antigravity/account.rs`
- `src/adapters/antigravity/account/credential_store.rs`
- `src/core/update.rs`
- `src/cli/args.rs`
- `src/cli/mod.rs`

## R12-1 隔离改名不在事务内，回滚时用户收不到任何提示

`quarantine_unmigratable` 的改名是非事务性的，`restore_published_transactions` 不会撤销它。
第二轮把 `report_migration_skips` 收进了 `outcome.is_ok()` 之后，
于是"改名已经发生、但事务回滚了"这种情况下用户什么提示都收不到，磁盘上却已经多了隔离文件。

- AC-R12-1.1 事务回滚时，已经发生的隔离改名必须对用户可见（或被撤销）。二选一，说明理由。
- AC-R12-1.2 测试覆盖"隔离已发生 + 事务失败"这条路径。

## R12-2 超大孤儿 stage 的删除丢掉了 digest 守卫且吞掉错误

正常路径用 `remove_evidence_exact(..., Some(digest))` 做按内容精确删除，
超大分支改成裸 `capability.remove` 并 `let _ =` 吞错，
既失去与并发写入的竞态保护，也不留任何痕迹。

- AC-R12-2.1 超大孤儿文件的删除必须保留"只删我认得的那个文件"的语义，
  或者明确降级为跳过并提示，不得静默裸删。
- AC-R12-2.2 错误不得被 `let _ =` 吞掉。

## R12-3 隔离名耗尽后的错误没有可执行的下一步

`quarantine_destination` 在候选名字全被占用时返回 Conflict，
消息只说 names are exhausted，用户会陷入每条命令都失败且无从下手。

- AC-R12-3.1 错误信息必须指出该清理哪个目录下的哪一类文件。

## R12-4 ASCII-only 约束只堵了两个出口

`ascii_console` 只用在 `report_migration_skips` 与 `ensure_import_kind_compatible`，
`sagy add` 成功时仍原样输出 email，非 ASCII email 会破坏项目的 console ASCII-only 约束。

- AC-R12-4.1 所有会把用户提供的字符串打到控制台的出口统一走同一个转义函数。
- AC-R12-4.2 给出你如何确认没有遗漏出口的方法。

## R12-5 self_update 的临时目录 fallback 删除范围过大

`temp_dir` 的 fallback 在 `parent()` 为 `None` 时会把整个 tmp root 删掉，
删除范围大于本次 staging 目录。

- AC-R12-5.1 清理范围必须严格限定在本次创建的 staging 目录。

## R12-6 `--oauth` 的 clap help 与新的文档约定冲突

第二轮在 `CLAUDE.md` 写死了"不得在代码/帮助文本/文档里把任何路径描述成 OAuth login"
（因为实现只是让用户粘贴一个已有 token，没有任何 OAuth 授权流程），
但 `--oauth` 的 clap help 当前正是 "Force the interactive OAuth login flow"。

- AC-R12-6.1 按实现据实改写这条 help 文案。
- AC-R12-6.2 顺带核对 `args.rs` 里其它 help 文案是否有同类夸大。
