# T1 state root 可用性与写读不变量对称（P0）

先读 `backlog/tasks-v3/COMMON.md`。
问题背景见 `backlog/reviews/2026-08-25-post-refactor-audit.md` 的 ROOT-001、ROOT-002、
STATE-002'、以及 P3 的 `encode_v2`、last-known-good、legacy storage 三条。

## 归属文件（只能改这些）

- `src/core/state_store.rs`
- `src/core/atomic_io.rs`
- `src/core/atomic_store.rs`
- `src/core/storage.rs`
- 新建：`tests/p0_state_root_layout.rs`

## AC-1（P0）安装器布局不得让 sagy 不可用

`SAGY_HOME` 同时是安装目录和 state root，安装脚本必然在其中创建 `bin/` 和 `tmp/`。

- AC-1.1 `~/.sagy` 下存在 `bin/` 目录时，`sagy list` 成功且 exit 0。
- AC-1.2 全新 root（尚无 state.json）下只有 `tmp/` 时，`sagy list` 成功且 exit 0。
- AC-1.3 root 下存在与 sagy 无关的条目（例如 `notes.txt`、`.DS_Store`、`backup/` 目录）时，
  `sagy list` 与一次会写 state 的命令（例如 `sagy import-known`）都成功且 exit 0。
- AC-1.4 上述陌生条目在命令执行前后**内容与 mtime 不变**，sagy 不得删除、移动或改写它们。
- AC-1.5 sagy 自己管理的条目仍然严格校验：`state.json` 是 symlink、`accounts` 是 symlink 或普通文件、
  `repo-sync.json` 超过上限时，仍必须拒绝并返回非 0。
- 说明：修复方向是"未知的顶层条目一律忽略、不纳管、不触碰"，而不是把白名单扩大成一张永远追不上的清单。

## AC-2（P0）当前工作目录不是安全边界

- AC-2.1 `cd ~/.sagy && sagy list` 成功且 exit 0。
- AC-2.2 `cd <ANTIGRAVITY_CONFIG_DIR> && sagy list` 成功且 exit 0。
- AC-2.3 仍然拒绝把 state root 指向文件系统根、`$HOME` 本身、系统临时目录本身：
  `sagy --state-dir $HOME list` 必须非 0 退出。

## AC-3（P1 的一半）v1 解析要丢弃占位账号

`src/core/storage.rs` 的 `cleanup_invalid_legacy_accounts` 证明真实 v1 state 里存在
`email == "google_accounts"` 且 `oauth_token`/`api_key`/`refresh_token` 全空的占位账号，
但生产 v1 读路径 `parse_v1` 没有继承这段清理，导致这类账号进入迁移并炸掉整笔迁移（见 T2）。

- AC-3.1 含该占位账号的 v1 `state.json` 被读取时，占位账号必须被丢弃且不出现在后续账号列表里。
- AC-3.2 丢弃行为不得影响同一份 state 里其它正常账号的读取。

## AC-4（P2）既有宽权限凭据要迁移收紧

- AC-4.1 把 `~/.sagy/accounts/<id>/` 下的凭据文件 `chmod 0644`、把 `accounts/` 目录 `chmod 0755` 之后，
  执行任意一条会打开 state 的命令，权限必须被收紧回 `0600`/`0700`。
- AC-4.2 收紧失败（例如 chmod 返回错误）必须 fail-closed，返回非 0，而不是继续使用。

## AC-5（P3）写入端与读取端不变量对称

- AC-5.1 提交一份超出读取端上限的 state（账号数超上限、或文档超大小上限）必须在**写入时**就被拒绝，
  不得出现"写成功但下一次读直接失败"的状态。

## AC-6（P3）损坏 state 的恢复路径

- AC-6.1 `state.json` 被截断/写入非法 JSON 后，命令失败的错误信息必须明确告诉用户
  可以怎么恢复（例如指出被隔离到哪个文件名、或指出可以执行哪条命令），而不是只报一句解析错误。
- AC-6.2 恢复动作不得静默丢弃用户数据：损坏的原文件必须被保留（改名隔离），不能直接删除。

## AC-7（P3）legacy storage 收口

- AC-7.1 `src/core/storage.rs` 里"读"路径不得再有写副作用（不得在 load 里物化 secret 文件）。
- AC-7.2 该路径上任何 I/O 或 chmod 错误必须传播，不得 `let _ =` 吞掉。
- AC-7.3 若某个 legacy `pub` 项在全库已无生产调用方，降为 `pub(crate)` 或删除；
  删除时必须同步更新引用它的既有测试，不得让测试继续验证一个已被生产路径弃用的 API。

## 自检

除通用门禁外，必须能给出 AC-1.1 / AC-1.2 / AC-1.3 / AC-2.1 的黑盒复现命令与实际输出。
