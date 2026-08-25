# R1 state store 复核回归

先读 `backlog/tasks-v3/round2/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round2/R1`

## 归属文件

- `src/core/state_store.rs`
- `src/core/atomic_io.rs`
- `src/core/atomic_store.rs`
- `src/core/storage.rs`
- `tests/p0_state_root_layout.rs`
- `tests/p0_state_load_boundaries.rs`
- `tests/windows_runtime.rs`
- `tests/p0_repo_boundaries.rs`

## R1-1（BLOCKER）损坏 state 的隔离打击面过大，会静默丢账号列表

`quarantine_unreadable_document` 现在的门槛是"重读一遍还是 parse 不过"，
而 `parse_snapshot` 的失败远不止"非法 JSON"，还包括：

- `unsupported state version {version}`（用户先跑新版写出 v3，再跑一次旧二进制）
- `v2 state revision must be positive`
- `v2/v1 state exceeds bounded collection limits`
- `validate_state_invariants` 的全部失败（重复 id、current account 不存在、usage_cache 悬空）

这些都是**读得出来、能人工修**的完好文档。现在只要执行一条只读的 `sagy list`，
它们就会被改名成 `state.json.corrupt-<uuid>`，用户接着敲一条 `login` 就会提交一份全新的空 state，
旧文档永久变成孤儿。

- AC-R1-1.1 只有 **JSON 语法层**失败（截断、非法 JSON 字节）才触发隔离。
- AC-R1-1.2 语义校验失败（版本不支持、invariant 违规、超出集合上限）必须原样上抛，
  **不得改名、不得移动** state.json。
- AC-R1-1.3 必须有测试覆盖"更高版本号的 state.json 被旧二进制读到"这一场景，
  断言文件在命令失败后仍在原位且内容逐字节不变。

## R1-2（MAJOR）AC-5.1 文档大小上限没有回归覆盖

现在只有一个直接调用内部函数的单测，把 `encode_v2` 里的调用点删掉测试照样绿。

- AC-R1-2.1 加一个测试，使得删掉 `encode_v2` 中的大小/集合上限调用点会让它变红。

## R1-3（MAJOR）AC-4.2 chmod fail-closed 没有覆盖

现有测试打在一条 HEAD 上本来就存在的 symlink 拒绝分支上；把
`fs::set_permissions(...)?` 改回 `let _ = ...`、把 chmod 后复核整段删掉，测试一样绿。

- AC-R1-3.1 让"chmod 之后复核发现权限没真正变紧就 bail"这条路径有测试覆盖。
  非 root 环境无法让 chmod 真的失败，所以请把复核逻辑做成可注入/可直接调用的形状，
  测试直接驱动它，并在测试注释里说明为什么不能走端到端。
- AC-R1-3.2 反向验证：删掉复核的 bail 分支，该测试必须变红。

## R1-4（MAJOR）三个死 pub 未删

`storage::load_state`、`storage::save_state`、`storage::write_file_atomically`
在 src/ 下零生产调用点（唯一命中是 `src/cli/mod.rs` 里一条反向守卫单测的字符串）。

- AC-R1-4.1 删除这三个符号。
- AC-R1-4.2 同步重写 `tests/p0_state_load_boundaries.rs`、`tests/windows_runtime.rs`、
  `tests/p0_repo_boundaries.rs` 中引用它们的用例，**改为驱动生产读路径**
  （`StateStore` / `StateSession`），使这些 P0 边界断言重新守在真实路径上。
  这几个文件里原有的安全断言（symlink 拒绝、路径逃逸、重复 id、权限）一条都不能丢。
- AC-R1-4.3 `src/cli/mod.rs` 里那条守卫单测不在你的归属里，不要改；
  如果删除后它会失败，在报告里写明。

## R1-5（MAJOR）锁等待必须可诊断（从 T5 移交）

全仓所有 flock 都是无超时的 `lock_exclusive`，无 stale 检测。
第一轮 T5 只在 `launcher.rs` 的一个调用点外面包了提示，但真正先阻塞的锁在更早的
`switch_account_session` 里（account.rs / active_home.rs），提示永远打不出来。

- AC-R1-5.1 在**加锁层**（atomic_io / atomic_store）实现通用能力：
  等待超过一个阈值仍未拿到锁时，向 stderr 打印一条 ASCII 提示，说明正在等待另一个 sagy 会话。
- AC-R1-5.2 提示至多打印一次，且不得在锁立刻可得时打印（快路径零开销、零延迟）。
- AC-R1-5.3 实现不得引入"通知丢失导致主线程被 join 拖住"的竞态
  （第一轮 T5 的 Condvar 实现就有这个问题：等待前不检查完成标志）。
- AC-R1-5.4 测试必须驱动"另一个进程/线程真的持有锁"的场景，而不是断言内部 helper 的返回值。

## R1-6（MINOR）

- AC-R1-6.1 `harden_state_root_permissions` 现在跑在 root 校验之前，会先 chmod 一批
  随后就要被判非法的文件，还把 `validate_accounts_dir` 更精确的错误文案顶掉。调整顺序。
- AC-R1-6.2 超过读取上限（16MB）的 state.json 现在永远不会被隔离，用户只拿到一句
  没有恢复指引的错误。让这条入口也给出与 R1-1 一致的可操作提示（注意：它属于"读得出来的坏"，
  按 R1-1 的规则不隔离，但必须有指引）。
- AC-R1-6.3 `filesystem_root_is_still_refused_as_a_state_root` 只断言退出码非 0，
  任何原因失败都算通过；补上 `std::env::temp_dir()` 这一条并断言拒绝原因。
