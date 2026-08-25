# T4 账号池同步的数据安全与可用性（P1）

先读 `backlog/tasks-v3/COMMON.md`。
背景见审计报告的 SYNC-101、SYNC-102，以及 P3 的 pool_id、tombstone、v1 bundle、
单账号阻断整包、tmp checkout 回收、URL 校验两份副本。

## 归属文件（只能改这些）

- `src/adapters/antigravity/repo_sync.rs`
- `src/adapters/antigravity/repo_bundle.rs`
- `src/cli/repo_sync.rs`
- 新建：`tests/p1_repo_sync_pool.rs`

不要改 `src/cli/args.rs` / `src/cli/mod.rs` / `src/cli/help.rs`（属于 T7）。
`RepoSyncOptions.include_all` 是死字段，由验收方在合并时统一删除，你既不要读它也不要删它。

## AC-1（P1）push 不得覆盖别人推上去的账号

- AC-1.1 本地 generation 落后于远端 bundle 时，`sagy push` 必须**拒绝**并给出可操作提示
  （提示用户先 pull），exit 非 0，且远端 bundle 文件内容不变。
- AC-1.2 先 pull 再 push 的正常流程必须成功，且结果 bundle 同时包含双方的账号。
- AC-1.3 远端不存在 bundle（首次 push）与远端 bundle 语义等价（no-op）两条路径不得被本改动破坏。
- AC-1.4 回归测试必须用本地 bare 仓库做真实 round-trip：
  A push -> B pull -> B 新增账号 push -> A 不 pull 直接 push（必须失败）-> 第三个全新目录 pull 后
  仍能看到 B 新增的账号。

## AC-2（P2）pull 要按凭据指纹去重

- AC-2.1 本地已存在凭据材料完全相同但 account id 不同的账号时，pull 不得再插入一个重复账号。
- AC-2.2 pull 之后本机 `sagy push` 必须能成功执行（不得出现 pull 制造出 push 永久失败的死局）。
- AC-2.3 若确实检测到本地重复，错误或提示信息必须指出**具体哪两个账号**重复以及建议保留哪一个。

## AC-3（P3）账号删除必须能传播

- AC-3.1 机器 A 删除账号后 push，机器 B pull 时该账号必须从 B 的 state 中移除，
  且其凭据文件不得被重新写回磁盘。
- AC-3.2 删除记录必须有界（不能无限增长），并说明你选择的上限或过期策略。
- AC-3.3 删除传播不得误删机器 B 上本地新增、尚未 push 的账号。

## AC-4（P3）同一仓库的不同 URL 写法必须视为同一个池

- AC-4.1 `https://host/u/r.git`、`https://host/u/r`、`git@host:u/r.git`、`ssh://git@host/u/r.git`
  必须解析到同一个 pool。用其中任一写法 push、再用另一写法 pull，必须成功。
- AC-4.2 真正不同的仓库仍必须被判为不同 pool。
- AC-4.3 当确实发生 pool 不匹配时，错误信息必须说明原因和恢复办法，不能只丢一句
  "belongs to a different account pool"。

## AC-5（P3）老仓库不得被永久锁死

- AC-5.1 远端是旧版本 bundle 时，`sagy pull` 与 `sagy push` 至少有一条路径能让用户自助恢复
  （自动迁移，或明确告知需要执行什么、删除哪个文件）。
- AC-5.2 无论选哪种方式，都不得在未经用户确认的情况下静默丢弃远端已有账号。

## AC-6（P3）单个坏账号不得阻断整包 push

- AC-6.1 某一个账号的凭据文件缺失/损坏时，`sagy push` 必须仍能把其余健康账号推上去，
  并用 ASCII 提示列出被跳过的账号。
- AC-6.2 全部账号都不可导出时才允许失败，且错误信息要说明原因。

## AC-7（P3）临时 checkout 要能回收，且不与并发进程抢共享目录

- AC-7.1 进程被 SIGKILL 后残留的 `tmp/repo-sync-*` 目录，必须在下一次 repo sync 命令时被回收。
- AC-7.2 回收逻辑不得删除仍在被其它进程使用的目录。
- AC-7.3 清理路径不得删除共享的 `tmp/` 根目录本身（这会与并发进程的"先判断存在再写入"形成竞态）。

## AC-8（P3）repo URL 信任边界只能有一份实现

- AC-8.1 CLI 侧"凭据 URL 绝不落盘"与 adapter 侧"凭据 URL 绝不进 argv"必须调用**同一个**校验函数。
- AC-8.2 既有的拒绝规则（带 userinfo 的 URL、含 query/fragment、SCP-like 带密码）一条都不能放宽，
  相关既有测试必须继续通过。

## 自检

除通用门禁外，AC-1.4 与 AC-4.1 必须给出本地 bare 仓库的真实 round-trip 复现记录。
