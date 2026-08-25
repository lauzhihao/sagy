# T3 active-home 崩溃恢复（P1）

先读 `backlog/tasks-v3/COMMON.md`。背景见审计报告的 HOME-001。

## 归属文件（只能改这些）

- `src/adapters/antigravity/active_home.rs`
- 新建：`tests/p1_active_home_recovery.rs`

## 问题摘要

`publish_inner` 先把用户真实的 `~/.gemini/oauth_creds.json`、
`~/.gemini/antigravity-cli/antigravity-oauth-token` move 成 tombstone，再 move stage 到位，
**最后**才写 `Published` journal。`JournalPhase` 只有 `Prepared`/`Published` 两相。
崩溃落在中间时 journal 停在 `prepared`，而 `recover_pending` 对 `prepared` 只调用
`cleanup_prepared_inner`，后者要求 live layout 与 baseline 精确一致，必然 bail。

关键观察：`restore_inner` 已经能处理这个中间态（它会把 tombstone move 回 target），
缺的是**相位表达与恢复分支路由**，不是恢复能力。

## AC-1（P1）任意崩溃点都必须能自愈

- AC-1.1 在"真实凭据已被 move 成 tombstone、stage 尚未就位"的状态下，
  下一次任意 sagy 命令必须成功（exit 0），且用户真实凭据文件必须回到原位、内容逐字节一致。
- AC-1.2 在"部分 slot 已 move 到位、部分未 move"的状态下，同样必须成功恢复到一个自洽状态
  （要么全部回滚到 baseline，要么全部前滚到目标），不得停在中间态。
- AC-1.3 恢复之后 `sagy use` / `sagy rm` / `sagy list` 必须都能正常执行——
  不能出现"恢复成功但下一条命令仍然 bail"的情况。
- AC-1.4 恢复过程不得删除任何含凭据的文件；tombstone 只能被移回或在确认目标已就位后才清理。

## AC-2（P1）测试必须覆盖真实崩溃窗口

- AC-2.1 回归测试必须**直接构造磁盘上的中间态**（写出 tombstone + `prepared` journal），
  而不是只调用一个内部函数看它返回 Ok。
- AC-2.2 测试必须断言用户真实凭据文件的内容在恢复后与崩溃前逐字节一致。
- AC-2.3 覆盖至少两个崩溃点：move 循环开始后第一个 slot 之后、以及 stage move 完成但 journal 未写之前。

## AC-3（P3）不留孤儿 stage

- AC-3.1 恢复路径必须清理 `~/.gemini` 及其子目录下无主的 `.sagy-active-home-*.stage` 文件
  （这些文件含完整凭据明文）。
- AC-3.2 只清理无主的，不得误删属于进行中事务的文件。

## 自检

除通用门禁外，必须能给出 AC-1.1 的复现：手工造中间态 -> 跑真实二进制 -> 贴 exit code 与恢复后的文件校验和对比。
