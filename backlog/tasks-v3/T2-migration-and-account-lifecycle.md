# T2 v1 迁移逃生阀与账号/凭据生命周期（P1）

先读 `backlog/tasks-v3/COMMON.md`。
背景见审计报告的 MIG-001，以及 P3 的 API key 去重、`--project-id`、跨类型导入、孤儿 stage、env 继承。

## 归属文件（只能改这些）

- `src/adapters/antigravity/account.rs`
- `src/adapters/antigravity/account/credential_store.rs`
- `src/core/credential.rs`
- 新建：`tests/p1_legacy_migration.rs`

注意：`src/core/state_store.rs` 的 `parse_v1` 由 T1 负责丢弃占位账号，你不要改那个文件；
你要解决的是"即使仍有一个账号不可迁移，整笔迁移也不能失败"。

## AC-1（P1）迁移必须能跳过坏账号

- AC-1.1 一份 v1 state 里有 1 个正常 OAuth 账号 + 1 个不可迁移账号
  （凭据文件被删、内嵌 token 为空、目录里是错类型的凭据、只有孤立 refresh_token 之一即可），
  执行 `sagy list` 必须 exit 0，并列出那个正常账号。
- AC-1.2 同样的 state 下 `sagy rm <正常账号 email>` 必须能执行成功——
  即用户必须始终有办法用 CLI 管理账号，不能因为另一个账号坏了就锁死整个 CLI。
- AC-1.3 被跳过的账号必须对用户可见：命令输出里要有一条 ASCII 提示，
  说明哪个账号（用 email 或 id）因为什么原因被跳过。
- AC-1.4 被跳过的账号的原始数据不得被删除或覆盖（隔离/保留，不销毁）。
- AC-1.5 全部账号都不可迁移时，命令仍必须 exit 0 并给出可操作的提示，而不是硬失败。

## AC-2（P3）同一凭据材料必须去重

- AC-2.1 用同一把 API key、但两次给不同的 `--email`（或不同 `--project-id`）导入，
  最终只能存在**一个**账号、一份凭据副本。
- AC-2.2 `sagy list` 对上述场景只显示一个候选。
- AC-2.3 现有 doc comment 声称"exact material duplicate 会复用 id，即使 caller 给了不同 email hint"，
  实现必须与该表述一致；若你选择改表述而不是改行为，必须说明理由。

## AC-3（P3）静默无效的参数必须显式处理

- AC-3.1 给 API key 账号传 `--project-id` 时，要么在启动时真正生效，要么明确拒绝/警告；
  不允许既不生效、又静默参与凭据指纹计算。
- AC-3.2 无论选哪种处理方式，都不得让同一把 API key 因为 `--project-id` 不同而产生两个账号。

## AC-4（P3）跨类型 email 冲突要有出路

- AC-4.1 已存在 ApiKey/Vertex 账号的 email 再用于导入 OAuth token 时，
  错误信息必须说明冲突对象和可执行的下一步（例如提示先删除哪个账号）。
- AC-4.2 交互式录入路径不得在用户已经粘贴完 secret 之后才发现该冲突——冲突检测必须前置到读取 secret 之前。

## AC-5（P3）崩溃后不留明文凭据孤儿文件

- AC-5.1 在 stage 文件已写、journal 尚未写的窗口崩溃后，下一次任意命令必须清理掉
  `~/.sagy/accounts/<id>/` 下无主的 `*.stage` 凭据文件。
- AC-5.2 清理只针对无主（journal 里没有对应记录）的 stage 文件，不得误删正在进行中的事务文件。

## AC-6（P3）子进程认证环境按 deny-by-default 收口

- AC-6.1 父进程设置了 `GOOGLE_API_KEY`、`GOOGLE_GENAI_USE_VERTEXAI`、`GOOGLE_CLOUD_LOCATION`
  等与 Google 认证相关的变量时，agy 子进程不得继承到与当前账号无关的认证变量。
- AC-6.2 该收口只能通过你归属文件里的账号/凭据侧接口表达。
  如果收口必须发生在 `launcher.rs`（属于 T5），不要改那个文件，在报告里写明需要 T5 配合的具体变量清单。

## 自检

除通用门禁外，AC-1.1 与 AC-1.2 必须能给出黑盒复现：构造 v1 `state.json` -> 跑真实二进制 -> 贴输出与 exit code。
