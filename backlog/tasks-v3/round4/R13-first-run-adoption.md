# R13 首次接管既有 Antigravity 凭据（P0）

先读 `backlog/tasks-v3/round4/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round4/R13`
问题详情见 `backlog/reviews/2026-08-25-post-refactor-audit.md` 的 **HOME-002**。

## 归属文件

- `src/adapters/antigravity/active_home.rs`
- `src/adapters/antigravity/account.rs`
- `src/cli/mod.rs`
- `src/cli/args.rs`
- `README.md`
- `README.zh-CN.md`
- 新建：`tests/p0_first_run_adoption.rs`

## 现象（我已实测复现，见 `backlog/verify/t11-first-run.sh`）

机器上本来就在用 Antigravity（`~/.gemini/antigravity-cli/antigravity-oauth-token` 已存在）：

```text
$ sagy import-known      -> Imported account: antigravity-user@gemini    OK
$ sagy list              -> 正常显示该账号                                OK
$ sagy                   -> Error: invalid state: active-home has unmanaged or
                            mismatched fixed slots; explicit adopt/takeover is required
                            agy 从未被 spawn
```

第二条路径：用户删掉 `~/.sagy` 重来，此后 `sagy login` 与 `sagy launch` 双双失败。

根因：`src/cli/mod.rs` 的 5 个调用点全部硬编码 `ActiveHomeAdoption::Strict`；
`Adopt` 与 `Takeover` 分支（`account.rs:948-950`）没有任何 CLI 入口。
错误信息要求用户做一件 CLI 没有提供的事。

## AC-1（P0）主线上手路径必须通

- AC-1.1 `~/.gemini` 下已有凭据的机器上，`sagy import-known` 之后直接执行 `sagy`
  必须成功启动 agy（exit 0，且 agy 真的被 spawn）。
- AC-1.2 用户删掉 `~/.sagy` 之后重新 `sagy login`，再 `sagy`，必须成功。
- AC-1.3 这两条路径都不得要求用户手工删除 `~/.gemini` 下的任何文件。

## AC-2（P0）不得静默覆盖用户的既有凭据

这是 `ec18dfc` 引入 active-home 事务层的**初衷**，不能为了让 AC-1 通过就一刀切放开。

- AC-2.1 当 active home 里的凭据**就是**某个已登记账号的凭据（内容一致）时，
  直接接管（adopt），不需要用户做任何事——AC-1 覆盖的正是这一类。
- AC-2.2 当 active home 里的凭据 sagy 不认识（不属于任何已登记账号）时，
  **不得**静默覆盖。此时必须：
  (a) 明确告诉用户 active home 里有一份不属于 sagy 管理的凭据；
  (b) 说明这份凭据会被移动到哪里（备份位置）或如何自行备份；
  (c) 给出一条**用户真的可以执行的 sagy 命令**来完成接管。
- AC-2.3 接管动作执行后，被替换掉的原凭据必须可恢复（保留备份，不得直接销毁）。
- AC-2.4 所有提示 ASCII only。

## AC-3 逃生口必须是显式的、被文档记录的

参照 `--insecure-host-key` 的既有模式：默认安全，逃生口显式 opt-in。

- AC-3.1 新增的命令或参数必须出现在 clap 的真实 help 输出里，并有说明文字。
- AC-3.2 两个 README 的命令/参数表同步补上，说明什么时候需要它、它会动哪些文件。
- AC-3.3 不得引入第二条与 `--insecure-host-key` 风格不一致的逃生口设计。

## AC-4 回归测试

- AC-4.1 新建 `tests/p0_first_run_adoption.rs`，覆盖 AC-1.1 / AC-1.2 / AC-2.1 / AC-2.2 四条，
  全部驱动真实二进制 + 隔离 HOME + 假 agy。
- AC-4.2 每条都做反向验证：把修复改回硬编码 `Strict`，对应用例必须变红。
- AC-4.3 既有的 active-home 崩溃恢复测试（`tests/p1_active_home_recovery.rs`）一条都不能弄红。
  该文件**不在**你的归属里，不要改它。

## 参考

主仓库里已经有一份黑盒验收脚本 `backlog/verify/t11-first-run.sh`（当前 2 PASS / 8 FAIL）。
你可以把它拷进工作副本跑，但**不要修改它**——它是验收方的判据。
