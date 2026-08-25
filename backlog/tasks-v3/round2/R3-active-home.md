# R3 active-home 复核回归

先读 `backlog/tasks-v3/round2/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round2/R3`

## 归属文件

- `src/adapters/antigravity/active_home.rs`
- `tests/p1_active_home_recovery.rs`

## R3-1（MAJOR）核心松弛判据零覆盖

`slot_state_is_explained`（tombstone 松弛判据）被现有 6 个用例完全绕过：
把它改回 `slot_digest_matches` 全部照样绿。原因是 fixture 造的两个场景都是**跨槽位**切换
（账号 A 占 token 槽、账号 C 占 document 槽），两个槽位在旧判据下就已经返回 true。

只有 baseline=Some(A)、target=Some(B) 且**同一槽位**（两个账号同为 raw-oauth，
或同为 authorized-user）互切时，旧判据才会 bail `active-home restore observed an unknown live digest`。
这恰恰是最常见的真实切号形态。

- AC-R3-1.1 新增用例：同槽位 A -> B 切换，在 tombstone 已生成、stage 未就位的崩溃点恢复，
  断言恢复成功且 A 的凭据逐字节回到原位。
- AC-R3-1.2 反向验证：把 `slot_state_is_explained` 改回 `slot_digest_matches`，该用例必须变红。
- AC-R3-1.3 `published` 相位预检松弛（`active_home.rs` 里第三个调用点）同样补一个能反向验证的用例。

## R3-2（MINOR）

- AC-R3-2.1 孤儿 stage 清理用裸 `fs::symlink_metadata` 且对错误硬失败：
  一个 stage 文件在 `read_dir` 与 `symlink_metadata` 之间消失，就会把每条 sagy 命令变成 rc=1。
  这正是本工单要消灭的那类"恢复路径自己制造死锁"。改成容忍 NotFound。
- AC-R3-2.2 AC-3.2"不得误删进行中事务的文件"现在只有白盒单测断言内部函数返回值；
  补一个端到端用例：造一个真实的进行中事务现场，断言它的 stage 文件在 sweep 后仍在。
- AC-R3-2.3 新引入的 `publishing` 相位在生产侧的写入没有任何覆盖
  （删掉 `publish_inner` 里那次 write_journal，6 个用例照样绿）。补上。
- AC-R3-2.4 prepared/publishing 恢复分支的 mode 从硬编码 Strict 改成读 journal 的 adoption_mode，
  这是超出原 AC 的行为变更且无覆盖。要么补测试，要么改回去，在报告里说明选择。
