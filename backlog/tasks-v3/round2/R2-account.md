# R2 账号与凭据复核回归

先读 `backlog/tasks-v3/round2/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round2/R2`

## 归属文件

- `src/adapters/antigravity/account.rs`
- `src/adapters/antigravity/account/credential_store.rs`
- `src/adapters/antigravity/auth.rs`
- `src/core/credential.rs`
- `tests/p1_legacy_migration.rs`

## R2-1（BLOCKER）API key 指纹变更让升级用户产生重复账号

第一轮把 API key 凭据文档从 `{"api_key":K,"email":E,"project_id":P}` 改成只含 `{"api_key":K}`，
指纹随之改变。而 ApiKey 导入走 `ImportMatch::IdentityOnly`，只比指纹、不比 email。

失败路径：用户在**升级前**执行过 `sagy add --api-key K --email a@x`（磁盘上的 credentials.json 含 email），
升级后再执行完全相同的命令 -> 新指纹 != 旧指纹 -> 新建第二个 uuid ->
state 里两个 email 相同、持同一把 key 的账号，accounts/ 下两份明文 key，policy 当两个候选调度。
这正是第一轮 AC-2 要消灭的现象，只是把触发条件从"不同 email"换成了"跨版本"。

- AC-R2-1.1 升级前用旧文档格式建立的 api_key 账号，升级后再次导入同一把 key 必须复用原账号，
  不得新建第二个账号、不得写出第二份凭据副本。
- AC-R2-1.2 测试必须**从旧格式的磁盘现场起步**（手工写出含 email/project_id 的 credentials.json
  和对应的 state），而不是从空 state 起步。
- AC-R2-1.3 反向验证：撤掉兼容匹配，该测试必须变红。

## R2-2（MAJOR）交互式 add 仍然先读完 secret 才发现冲突

`auth.rs` 的 OAuth 交互分支先 `rpassword::prompt_password` 读完 token，
再进 import 才触发跨类型冲突检查。auth.rs 这一轮在你的归属里，把检查前置。

- AC-R2-2.1 email 已被 ApiKey/Vertex 账号占用时，交互式录入必须在**提示用户粘贴 secret 之前**
  就报错退出。
- AC-R2-2.2 错误信息说明冲突对象与下一步（提示先删除哪个账号）。
- AC-R2-2.3 测试驱动真实的交互路径（可用管道喂 stdin），断言 secret 提示语从未出现。

## R2-3（MAJOR）GOOGLE_AUTH_ENV_VARS 是死表

`src/core/credential.rs` 新增的 `GOOGLE_AUTH_ENV_VARS` / `is_google_auth_env_var`
在 src/ 下没有任何调用点，安全收益为 0。真正的清理点在 `launcher.rs`（属 R5）。

- AC-R2-3.1 保证这张表的内容正确、完整、有序去重，并在报告里给出 R5 需要遍历的确切 API 形状。
- AC-R2-3.2 如果 R5 无法引用（模块可见性问题），在你的归属文件里把可见性调整好。
- 不要改 launcher.rs。

## R2-4（MINOR）

- AC-R2-4.1 `account_dir_present` 用裸 `fs::symlink_metadata` + `is_dir` 判断，
  把"accounts/<id> 是符号链接或普通文件"这类异常从硬错误静默降级成跳过（fail-open）。改回 fail-closed。
- AC-R2-4.2 孤儿 stage 文件大于 256 KiB 时清理逻辑会硬失败，进而让每条命令失败——
  与"下一次任意命令必须清理"的目标相反。超大孤儿文件必须能被清理或跳过，不得阻断 CLI。
- AC-R2-4.3 `report_migration_skips` 在迁移事务返回 Err、整体回滚时仍打印
  "was skipped / 原始数据已保留"，与实际结果矛盾。只在真正提交成功后才报告跳过。
- AC-R2-4.4 隔离目标文件已存在时 `move_file` 直接失败，会把"用户手工恢复凭据后重跑"变成又一次硬失败。
  隔离目标必须唯一化或可覆盖。
- AC-R2-4.5 skip 提示与跨类型冲突错误直接内插 v1 state 里的 email；
  非 ASCII email 会破坏项目的 console ASCII-only 约束。做转义或过滤。
