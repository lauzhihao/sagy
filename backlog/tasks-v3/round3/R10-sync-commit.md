# R10 pull 的协同提交在坏账号场景下仍会硬失败

先读 `backlog/tasks-v3/round3/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round3/R10`

## 归属文件

- `src/adapters/antigravity/repo_sync.rs`
- `src/core/state_store.rs`
- `tests/p1_repo_sync_pool.rs`

## 背景

第二轮把"删除传播撞上 `coordinated commit requires credential or active-home proof`"
这条硬失败修掉了一半：提交判据收紧成 `credential_refs_changed && !proofs.is_empty()`，
只覆盖了"一条 proof 都没有"的场景。

## R10-1（MAJOR）import 与坏账号删除同时发生时 pull 仍硬失败

只要同一次 pull 里**既有**需要落盘的 import（产生 proof）、**又有**凭据文件已缺失的
tombstone 删除（Delete 分支对空 layout 直接 `continue`，不产生 proof），
就会走 `commit_coordinated`，然后撞上 `state_store.rs` 的覆盖率校验：

```text
coordinated credential proof set does not cover every credential reference change
```

复现：alice 同一次会话 `add X` + `rm Y` 后 push；bob 本地 Y 的凭据文件已缺失 -> bob pull。
changed_ids={X,Y}，proof_ids={X}，硬失败。
第二轮新增的测试只构造了"其余账号全部 unchanged"这一种形态，盖不到。

- AC-R10-1.1 上述混合场景必须提交成功，X 被导入、Y 被移除。
- AC-R10-1.2 覆盖率校验的**安全意图**不得被削弱：凭据引用发生变化却拿不出证明的情况仍必须被拒绝。
  你需要的是一种能表达"该账号的凭据本来就不在磁盘上，所以没有可证明的对象"的证明形态，
  而不是把校验整个放行。在报告里论证你的方案为什么不会打开越权删除的口子。
- AC-R10-1.3 测试构造该混合现场，并做反向验证。

## R10-2（MAJOR）被删账号既是 current 又是坏账号时，pull 彻底卡死

第二轮在 pull 事务前无条件调用了完整的 `remove_account_session`，
而该事务对空 credential layout 会硬失败（`NotFound`，或 CurrentExact 模式下的 `Conflict`）。

被 pool 删除的账号如果恰好**既是本机 current account、凭据文件又已缺失**
（这正是账号被删的典型原因：凭据泄露后本机先手工删了文件），
该机器此后每一次 pull 都会失败，错误文案也没有恢复指引。
注意 `tombstone_applies` 只看 `state.credential_refs` 的指纹、不看磁盘，
所以坏账号照样被判定为"删除生效"，必然进入这条分支。

上一轮该场景只是打个 WARNING 继续（虽然行为是错的），这一轮变成了硬失败——属于新引入的失败路径。

- AC-R10-2.1 "被删账号既是 current、凭据文件又缺失"时 pull 必须成功：账号从 state 移除、
  current 指向被清空、给出 ASCII 提示。
- AC-R10-2.2 三种组合都要有测试：current+凭据完好、非 current+凭据缺失、current+凭据缺失。
- AC-R10-2.3 反向验证：把空 layout 的放行分支去掉，AC-R10-2.1 的测试必须变红。

## R10-3（MINOR）legacy pool id 兼容只认字节完全一致的写法

`legacy_pool_id_for_repo` 直接哈希当前传入的原始字符串，不做归一化。
存量 bundle 的 pool_id 是当年那次 push 用的**那个具体写法**算出来的；
用户今天换成等价写法（尾斜杠、`.git` 后缀、scp 形式 vs ssh:// 形式）仍会锁死。

- AC-R10-3.1 legacy 兼容必须覆盖同一仓库的常见等价写法集合，而不是单一字符串。
- AC-R10-3.2 说明你如何界定这个集合、代价是什么（每次多算几个哈希是可接受的）。

## R10-4（MINOR）tombstone 保全没有有牙的断言

AC"tombstone 不得在下一次 push 时丢失"的现有测试里，验证方要么是全新机器、
要么是删除发起方，两者都不会因为 tombstone 丢失而察觉。

- AC-R10-4.1 造一个能真正察觉 tombstone 丢失的验证者：
  一台**已经持有该账号**、但尚未 pull 到删除记录的机器，pull 后必须看到账号消失。
