# R4 账号池同步复核回归

先读 `backlog/tasks-v3/round2/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round2/R4`

## 归属文件

- `src/adapters/antigravity/repo_sync.rs`
- `src/adapters/antigravity/repo_bundle.rs`
- `src/cli/repo_sync.rs`
- `tests/p1_repo_sync_pool.rs`

## R4-1（BLOCKER）pool_id 归一化把存量仓库全部锁死

第一轮把 `pool_id_for_repo` 从 `sha256(原始 repo 字符串)` 改成 `sha256(canonical_repo_identity(repo))`，
但没有任何 legacy 兼容分支。所有已经存在的 v2 bundle 的 pool_id 都是用旧算法生成的，
升级后一律命中 `repository bundle belongs to a different account pool`，push/pull 双向永久锁死，
而错误信息给出的唯一恢复办法是删除远端 bundle 文件（会丢账号）。

这等于把第一轮 AC-5 要消除的"老仓库锁死"对 v2 bundle 重新制造了一遍。

- AC-R4-1.1 远端 bundle 的 pool_id 等于 `sha256(原始 repo 字符串)` 时必须被接受。
- AC-R4-1.2 接受之后的下一次 push 必须自动把 pool_id re-key 成规范形式，且不丢账号、不丢 tombstone。
- AC-R4-1.3 测试：造一个 pool_id 用旧算法生成的 bundle，pull 成功 -> push 成功 -> 
  再用另一种等价 URL 写法 pull 仍成功。
- AC-R4-1.4 反向验证：撤掉 legacy 兼容分支，该测试必须变红。

## R4-2（MAJOR）current-account 例外让删除被静默撤销

`apply_tombstones` 遇到"要删的账号正是本机 current account"时只打提示、`continue`，账号留在 state 里。
随后本机 push 时该账号既在 exported 里、tombstone 又被 `.filter(...)` 丢弃，
`record_local_deletions` 也不会补记，于是 bundle 重新携带该账号且不再带删除记录——
A 的删除对全体机器被静默撤销。

- AC-R4-2.1 被 pool 删除的账号必须无条件从本机 state 中移除（AC 原文是无条件的）。
  如果它恰好是 current account，改为清空 current 指向并提示，而不是保留账号。
- AC-R4-2.2 无论本机怎么处理，tombstone 都不得在下一次 push 时丢失。
- AC-R4-2.3 测试覆盖"被删的正是 current account"这条路径，断言第三台全新机器 pull 后看不到该账号。

## R4-3（MAJOR）删除传播在坏账号场景下把 pull 卡死

tombstone 删除的账号如果本地凭据文件已缺失（正是"坏账号"场景），Delete 分支
`if layout.token.is_none() && layout.document.is_none() { continue; }` 不产生 proof，
但 `credential_refs` 已变化，于是走 `commit_coordinated(&candidate, proofs)` 且 proofs 为空，
撞上 `coordinated commit requires credential or active-home proof` 硬失败，且无恢复指引。
bundle 里其余账号都 unchanged（删除传播的常态）时必然触发。

- AC-R4-3.1 这条路径必须成功提交，不得硬失败。
- AC-R4-3.2 测试构造该现场（本地凭据文件已被删除 + 远端 tombstone + 其余账号不变）。

## R4-4（MINOR）

- AC-R4-4.1 `clone_repo` 先 open 锁文件、再 flock，两步之间并发进程的 reclaim 可以把这个
  尚未上锁的锁文件当成残留删掉，此后该 checkout 在整个生命周期内失去保护。收紧顺序或改判据。
- AC-R4-4.2 "用 ASCII 提示列出被跳过的账号"目前只有格式化函数的单测，
  把 push 里整段 eprintln 删掉所有测试仍绿。补一个断言真实 stderr 的端到端用例。
