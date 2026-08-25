# sagy 重构后全库审计报告（2026-08-25）

## 审查基线

- 基线提交：`ec18dfc`（refactor(security): harden state and credential lifecycle）
- 上一份报告：[2026-08-24 全库代码审查](./2026-08-24-full-code-review.md)，基线 `584ec53`
- 本轮方式：对上一份报告 30 条 P0/P1/P2 逐条核对当前实现 + 对 `ec18dfc` 新增的 ~30k 行做独立缺陷扫描；
  每条结论经独立的对抗性复核（默认立场是"报告者错了"），关键项用隔离 `HOME` 的真实二进制实测
- 门禁状态：`cargo fmt --check` / `cargo clippy --all-targets -- -D warnings` / `cargo test --all-targets` 全绿
  （注意：`tests/windows_runtime.rs` 在非 Windows 平台执行 0 个测试）

## 上一轮报告的关闭情况

以下条目经核对**已真实修复**且有代码或回归测试佐证，本轮不再跟踪：

SEC-001、SEC-002、SUPPLY-001、AUTH-001、AUTH-003、AUTH-004、SYNC-001、SYNC-002、SYNC-004、
USAGE-002、USAGE-003、POLICY-001、STATE-001、STATE-003、WIN-001、CLI-001、CLI-002、CLI-005、
PATH-001、RELEASE-001、UPDATE-001、UPDATE-002、SYNC-005。

部分修复（本轮继续跟踪）：AUTH-002、AUTH-005、USAGE-001、STATE-002、STATE-004、CLI-003、CLI-004、bugs-005、bugs-010、bugs-014。

## 严重级别

- **P0**：产品在正常安装/正常使用路径上不可用，或可导致任意命令执行/越界写删
- **P1**：核心功能失效、数据（账号/凭据）丢失、崩溃后无法自愈
- **P2**：明确的正确性、可用性或恢复性问题
- **P3**：行为偏差、死代码、文档与实现不一致

---

## P0

### ROOT-001：state root 严格 inventory 拒绝安装器自己创建的 `bin/` 与 `tmp/`，安装后全部命令失败

- 位置：`src/core/state_store.rs:3274`、`src/core/state_store.rs:3296-3303`、`install.sh:5-8,214,230`、`install.ps1:31-43`
- 根因：`SAGY_HOME` 既是安装目录又是 state root（`src/core/storage.rs:13,41-44`）。
  `validate_inventory` 的白名单只放行 `state.json / accounts / repo-sync.json / tmp / runtime` 和固定的
  lock/journal/stage 条目，其余一律 `bail!("unknown state root entry")`；state 文档尚不存在时连 `tmp/` 都不放行
  （`bail!("state-less root contains non-atomic entry")`）。
- 实测（HEAD 构建的 `target/debug/sagy`，隔离 HOME）：

```text
空 root                              -> No accounts registered.            rc=0
mkdir ~/.sagy/bin                    -> unknown state root entry: bin      rc=1
全新 root 只有 tmp/                   -> state-less root contains non-atomic entry  rc=1
echo note > ~/.sagy/notes.txt        -> unknown state root entry: notes.txt rc=1
```

- 影响：按 README 的官方一键安装完成后，除 `update` 外每条命令立即失败
  （`src/cli/mod.rs:108-112` 只让 `Update` 在 `StateSession::open` 之前返回）。
  第二条独立触发路径：全新机器先执行 `sagy update`，`src/core/update.rs:114-136` 建出 `tmp/` 且只删自己的子目录，
  之后第一条 `sagy list` 同样失败。`install.sh:270-276` 用 `>/dev/null 2>&1` 吞掉失败，脚本仍打印安装成功。
- 未被发现的原因：CI 把 `SAGY_HOME` 指向 runner 的空临时目录，`tests/p0_checksum.rs` 的 valid 分支装的是假二进制。

### ROOT-002：当前工作目录被列入 protected，`cd ~/.sagy` 后所有命令失败

- 位置：`src/core/atomic_io.rs:1144-1146`
- 根因：`reject_protected_claim_path` 把 `std::env::current_dir()` 压入 protected 列表。
- 实测：`cd $HOME/.sagy && sagy list` -> `protected system directory cannot be claimed`，rc=1；换任意其它 cwd 即正常。
- 影响：cwd 不是安全边界，该判定没有任何安全收益，只制造与真实原因无关的随机故障。

---

## P1

### HOME-001：active-home publish 先删真实凭据后写 journal，崩溃后 recovery 硬失败并锁死 CLI

- 位置：`src/adapters/antigravity/active_home.rs:647-687`、`689-699`、`1084-1095`；`src/adapters/antigravity/account.rs:1333-1338`
- 根因：`publish_inner` 先把 `~/.gemini/oauth_creds.json`、`~/.gemini/antigravity-cli/antigravity-oauth-token`
  move 成 tombstone，再 move stage 到位，**最后**才写 `Published` journal。`JournalPhase` 只有
  `Prepared/Published` 两相，没有 credential_store 那样的中间相位。
  `recover_pending` 对 `prepared` 只调 `cleanup_prepared_inner`，而后者开头要求 live layout 与 baseline 精确一致，
  必然 `bail!("active-home prepared recovery observed an unexpected live layout")`。
- 关键点：`restore_inner` 其实完全能处理这个中间态（它会把 tombstone move 回 target），
  只是 `recover_pending` 只在 `published` 相位才路由到它——是**分支路由缺失，不是能力缺失**。
- 影响：切号途中被 SIGKILL/掉电，用户真实凭据变成隐藏 tombstone，此后
  `use / rm / login / launch / import` 全部失败（`account.rs` 的 7 个调用点无条件跑 recovery 并 `?` 上抛），
  只能手工改名恢复。

### MIG-001：v1→v2 迁移全有或全无，单个坏账号让除 `update` 外所有命令永久失败

- 位置：`src/adapters/antigravity/account/credential_store.rs:2452-2458`、`2493-2550`；
  `src/adapters/antigravity/account.rs:1346-1370`；`src/cli/mod.rs:360-378`
- 根因：`MigrationPlanner::plan` 对每个账号 `plan_account(..)?` 硬抛；`plan_account` 有多条硬失败分支
  （目录里出现错类型凭据 / 孤立 refresh_token / 无凭据文件且内嵌 token 为空 / Vertex 缺文件）。
- 强化证据：`src/core/storage.rs:308-326` 的 `cleanup_invalid_legacy_accounts` 专门丢弃
  `email == "google_accounts"` 且三个凭据字段全空的占位账号——说明这类账号在真实 v1 state 里出现过。
  而生产 v1 读路径 `src/core/state_store.rs:2757-2801` 的 `parse_v1` 没有继承这段清理，
  该账号会安然进入 `plan_account` 并炸掉整笔迁移。
- 影响：升级后 CLI 只剩 `sagy update` 可用。`sagy rm` 自己也要先跑迁移，所以用户无法删掉出问题的账号，
  没有 skip/quarantine 逃生阀，只能手工编辑 `~/.sagy/state.json`。

### SYNC-101：push 没有 divergence 门禁，落后于远端时整包覆盖远端账号池

- 位置：`src/adapters/antigravity/repo_sync.rs:548`、`594-607`
- 根因：push 的账号集合完全来自本地 `load_v2_bundle_accounts`，remote bundle 只用于取 `pool_id` 和 generation；
  `local_generation.max(remote_generation).checked_add(1)` 把"远端 generation 更高"当作正常输入吸收，
  随后用只含本地账号的 bundle 覆写。`rollback_decision` / `check_sync_watermark` 只在 pull 路径被调用。
  git 层也拦不住：每次是全新 `clone --depth 1`，`push origin HEAD` 恒为 fast-forward。
- 影响：A push {1,2,3} -> B pull 后加 4 push -> A 未 pull 直接加 5 push，远端变成 {1,2,3,5}，
  账号 4 及其 credential 从池中永久消失。

### AVAIL-001：探测端点不可达时全部账号 Ineligible，sagy 直接拒绝启动

- 位置：`src/core/policy.rs:65-72`、`src/adapters/antigravity/usage.rs:471-477`、
  `src/core/health.rs:521-534`、`src/cli/mod.rs:502-523`
- 根因：传输失败 -> `Timeout/Network` -> `HealthStatus::TransientFailure` -> `Eligibility::Ineligible`。
  `Unverified` 有 `local_credential_validated` 的 `Fallback` 兜底，`TransientFailure` 没有任何兜底。
- 影响：断网、公司代理、DNS 抖动、探测域名被墙时，`sagy launch` 打印"无可用账号"并 exit 1，
  agy 根本没有被 spawn——即使凭据完全有效、agy 自己的后端是通的。
  提示语 (`src/core/ui.rs:72-77`) 让用户去 `sagy add`，与真实原因完全不符。
  缓解：`src/core/health.rs:366-390` 的 `PROBE_TTL_SECS`(300) 让断网后 5 分钟内仍可用缓存启动。

---

## P2

| 编号 | 问题 | 位置 |
| :--- | :--- | :--- |
| OBS-001 | 429 观测对**整个 stderr buffer** 做 `deserializer.end()`，agy 多打一行日志即 `InvalidJson`，diagnostic 变 `None`，README 宣称的自动降级在真实 agy 下不可达 | `launch_observation.rs:269-291,517-521` |
| TTY-001 | launcher 无条件把 agy 的 stderr 改成 pipe，子进程 `isatty(2)` 恒 false，交互式 TUI 能力探测退化（相对 `584ec53` 的回归） | `launcher.rs:503-505` |
| LOCK-001 | launch 期间持 credential + 两个 active-home flock，全部 `lock_exclusive` 无 timeout / 无 stale 检测，第二个终端的 `sagy use` 静默永久阻塞 | `launcher.rs:313-368`、`atomic_io.rs:528-546`、`atomic_store.rs:940-956` |
| HTTP-400 | `classify_response` 无 400 分支，落入 `OtherTransient` -> `TransientFailure`。Google 对失效 API key 的既定响应就是 400，用户看不到 "Relogin Required" | `usage.rs:481-510`、`health.rs:512-520` |
| SYNC-102 | pull 只按 account id 合并，不按 fingerprint 去重；跨机器重复导入同一凭据后本机 `push` 永久报 duplicate fingerprint 且不提示删哪个 | `repo_sync.rs:279-283,373-400` |
| STATE-002' | 既有 0644 凭据文件不做权限迁移（新写入已无窗口）；`storage.rs` 的 legacy `create_secure_dir_all`/`write_secret_file` 仍有 rename-后-chmod 窗口 | `storage.rs:63-87,146-200`、`state_store.rs:3315-3369` |
| INSTALL-002 | `install.ps1` 解压到固定 `$SagyHome\tmp` 且成功路径不清理，残留旧 `sagy.exe` 让完整性守卫 fail-open，把上一版本当新版本装上 | `install.ps1:32,121-132,171` |
| CI-001 | `tests/p0_checksum.ps1` 从未被任何 workflow 引用；`install.ps1` 的 fail-closed 只有 Rust 侧的字符串断言 | `.github/workflows/ci.yml:38-52`、`release.yml:61-76` |
| HELP-001 | `help.rs:24-132` 的 `render_help`/`render_topic_help` 已无任何生产调用方，~110 行双语帮助成死代码，中文帮助对用户彻底消失，还有一个只断言自己的单测 | `src/cli/help.rs:24-149` |
| DOC-001 | `.project_map`、`CLAUDE.md` 目录结构、`backlog/README.md` 记分板全部过期（记分板仍写 BLOCKED，004a/013 仍标 FAIL，实际都已修复） | `.project_map`、`CLAUDE.md:26-67`、`backlog/README.md` |

---

## P3

**死代码 / 死参数**
- `--all`（push/pull 都接受，`include_all` 从未被读取）：`args.rs:91-92`、`cli/mod.rs:255`、`repo_sync.rs:468`、`help.rs:101-103`
- `login --oauth` 字段声明并出现在 help 中，代码从不读取：`args.rs:51-52,134-156`
- `update.rs:57-67` 的 `pub fn is_newer_version` 只被自身单测引用，且非法版本静默返回 false
- `usage.rs:159-161` 的 `mark_rate_limited`、`health.rs:317-329` 的 `is_healthy` 已是死代码，
  后者语义与 `policy::eligibility` 相反；`usage.rs:32` 与 `health.rs` 各有一份 PROBE_TTL 常量
- `storage.rs:90,142,328-360` 的 legacy `load_state/save_state` 仍是 `pub`，"读"里带 `write_secret_file` 副作用并吞掉 I/O 错误

**CLI 行为**
- `contains_flag` 只识别 `--model` 不识别 `-m`，`sagy -m X` 会让 agy 同时收到默认 `--model` 和 `-m X`：`launcher.rs:485,596-605`
- 带 prompt 启动是否注入 `--continue` 取决于是否额外传了无关 flag（bugs-010 原样开着）：`cli/mod.rs:346-356`、`router.rs:79-93`

**账号 / 凭据**
- 同一把 API key 只要 `--email` 或 `--project-id` 不同就生成第二个账号、第二份明文副本，被 policy 当两个候选调度：`credential.rs:342-352`、`account.rs:462-466`（doc comment 与实现相反）
- API key 账号的 `--project-id` 静默 no-op，却参与 fingerprint 从而破坏去重：`account.rs:280-288`、`launcher.rs:203-204`
- 同 email 跨 credential 类型导入以 "credential kind mismatch" 硬失败，交互式 `sagy add` 在用户粘贴完 token 之后才报错，无恢复指引：`account.rs:1151-1154`
- stage/backup evidence 先于 journal 写入，崩溃后在 `~/.sagy/accounts/<id>/` 与用户真实 `~/.gemini` 留下含明文凭据的孤儿 stage 文件，永不清理：`credential_store.rs:1247-1256`、`active_home.rs:604-617`
- 父环境的 `GOOGLE_API_KEY` / `GOOGLE_GENAI_USE_VERTEXAI` 仍被 child 继承（现有清理是 3 项 allowlist 而非 deny-by-default）：`launcher.rs:459-464`

**state / 恢复性**
- `state.json` 损坏后无 last-known-good，除 `update` 外全部命令失败，历史元数据全丢：`state_store.rs:886-899`
- `encode_v2` 不校验 MAX_ACCOUNTS/文档大小上限，可写出自己读不回来的 state：`state_store.rs:2981-3022`
- legacy 迁移无条件清空 `current_account_id` 与 `active_profile`，属静默行为变更且无提示：`account.rs:1407-1412`
- 时钟前跳期间记录的 cooldown（`started_at > now`）会被每次读取重建成新窗口，账号进入永久 cooldown 且 `refresh --force` 也穿不透：`health.rs:219-239,366-370`
- `tests/p0_state_load_boundaries.rs`、`tests/windows_runtime.rs` 打的是已被生产路径弃用的 legacy `storage::load_state/save_state`

**repo sync**
- `pool_id` 直接哈希 repo 原始字符串，`https://h/u/r.git`、`https://h/u/r`、`git@h:u/r.git`、`ssh://git@h/u/r.git` 派生 4 个不同 pool，换写法即永久 `belongs to a different account pool`：`repo_sync.rs:207-228`
- pull 只 merge 不删除、无 tombstone，本地已删除/已吊销的账号会连同 credential 复活到磁盘，删除永远无法传播：`repo_sync.rs:373-414`
- v1 bundle 无迁移路径，老仓库 push/pull 双向永久锁死且错误信息无指引：`repo_sync.rs:559,737,964-973`
- 单个账号 credential 读失败阻断整包 push，其余健康账号也备份不出去：`repo_sync.rs:261-281`
- `tmp/repo-sync-*` 临时 checkout 只靠 `Drop` 清理，SIGKILL 后每次失败累积一个 UUID 目录；`Drop` 里的 `remove_dir(parent)` 与并发的 `create_secure_dir_all` 存在瞬时 ENOENT 竞态：`repo_sync.rs:484-498,1060-1076`
- repo URL 信任边界校验存在两份手写副本，任一侧单独加固都会静默失配：`cli/repo_sync.rs:45-98`、`repo_sync.rs:1198-1246`

**launch**
- 父进程 stderr 写失败会让整次 launch 变成 `Err`，丢掉子进程退出码和已解析出的 429 证据：`launcher.rs:523-530`

**供应链**
- update 与两个安装脚本的下载路径均无 size 上限，只有超时：`update.rs:196-198,231-237`、`install.sh:74-85`、`install.ps1:47,61,71`
- release workflow 的第三方 Action 未按 commit SHA 固定，而 publish job 持 `contents:write`：`.github/workflows/release.yml:108-160`

**文档**
- `CLAUDE.md:69-71` 的测试指引缺凭据沙箱环境变量，与 `backlog/README.md:34-38` 的铁律和 CI 的做法冲突
- `--insecure-host-key` 这个会关闭 SSH host key 校验的开关在所有面向用户的文档里都不存在
- `SAGY_HOME` / `SAGY_POOL_REPO` / `SAGY_POOL_KEY` / `SAGY_UPDATE_REPO` / `ANTIGRAVITY_CONFIG_DIR` / `GEMINI_HOME` 与 repo 解析优先级无任何文档
- `README.md` / `README.zh-CN.md` / `ARCHITECTURE.md` 的命令表、目录结构、必填性三处与实现不符且两个 README 互不自洽
- `install.sh` 与 `install.ps1` 的 `sagy-original` 解析顺序不一致

---

## 补充证据（2026-08-25，验收脚本实测）

ROOT-001 还有一条更贴近真实用户路径的触发方式：**全新机器上的第一条 `sagy pull <repo>`**。
`repo-sync.json` 会在 `state.json` 之前落盘，随后 state-less root 校验把它判为非法条目：

```text
$ sagy pull <bare-repo>        # 全新 SAGY_HOME
Error: invalid state: state-less root contains non-atomic entry
$ ls -la ~/.sagy
-rw-------  repo-sync.json     # 只有这一个文件
```

同一次实测还直接复现了另外两条：

- **SYNC-101**：机器 A 落后于远端时 `sagy push` 返回 0 并覆盖远端，机器 B 推上去的账号消失。
- **pool_id 未规范化**：同一个本地裸仓库，`<path>` 与 `<path>/` 两种写法被判为不同的池，
  第二种写法直接 `repository bundle belongs to a different account pool`。

---

## 追加 P0（2026-08-25，三轮修复后由验收发现）

### HOME-002：已有 Antigravity 凭据的机器上，首次使用 sagy 必定卡死

前三轮修好 `ROOT-001` / `AVAIL-001` 之后，launch 路径第一次真正能跑通，
于是暴露出一条此前被它们挡住的缺陷。这是产品的**主线上手路径**：

```text
$ sagy import-known
Imported account: antigravity-user@gemini (ID: ...)     # 成功
$ sagy list
   antigravity-user@gemini  oauth  Antigravity OAuth  ...  # 正常显示
$ sagy
Error: invalid state: active-home has unmanaged or mismatched fixed slots;
       explicit adopt/takeover is required                  # agy 从未被 spawn
```

- 触发条件：`~/.gemini/antigravity-cli/antigravity-oauth-token`（或 `~/.gemini/oauth_creds.json`）
  在 sagy 接管之前就已存在。也就是**每一个已经在用 Antigravity 的用户**，即 sagy 的全部目标用户。
- 第二条触发路径：用户删掉 `~/.sagy` 想重来一次。此后 `sagy login` 与 `sagy launch` 双双失败。
- 根因：`src/cli/mod.rs` 的 5 个调用点全部硬编码 `ActiveHomeAdoption::Strict`
  （160/187/211/497/547），而 `Adopt` 与 `Takeover` 两个分支在
  `src/adapters/antigravity/account.rs:948-950` 存在却**没有任何 CLI 入口**。
- 因此错误信息要求用户执行一个 CLI 根本没有提供的动作，用户只能手工删除 `~/.gemini` 下的凭据文件。
- 验收脚本：`backlog/verify/t11-first-run.sh`（当前 2 PASS / 8 FAIL）。

### 另记：`import-auth` 的 authorized-user 最小字段集合需要与真实文件核对

`src/core/credential.rs:665` 要求 authorized-user 文档同时具备
`client_id` / `client_secret` / `refresh_token` / `token_uri` 四个字段。
gcloud 写出的 ADC 文件通常**不含** `token_uri`。该约束是 `ec18dfc` 基线自带的，
不是这三轮修复引入的，但需要拿真实的 `~/.gemini/oauth_creds.json` 核对一次，
否则 `sagy import-auth` 可能拒绝真实凭据文件。

---

## 修复与验收结论（2026-08-25 收尾）

分四轮执行，每轮都是「隔离副本实现 -> 独立对抗性复核 -> 验收方合并 -> 门禁 + 黑盒验收」。
工单在 `backlog/tasks-v3/`（T1-T9 / round2 R1-R9 / round3 R10-R12 / round4 R13）。

### 关闭状态

| 级别 | 条目 | 状态 |
| :--- | :--- | :--- |
| P0 | ROOT-001、ROOT-002、HOME-002 | 全部关闭，各有黑盒验收脚本 |
| P1 | HOME-001、MIG-001、SYNC-101、AVAIL-001 | 全部关闭 |
| P2 | OBS-001、TTY-001、LOCK-001、HTTP-400、SYNC-102、STATE-002'、INSTALL-002、CI-001、HELP-001、DOC-001 | 全部关闭 |
| P3 | 死代码/死参数、CLI 行为、账号凭据、state 恢复性、repo sync、供应链、文档 | 除下列"已知残留"外全部关闭 |

复核在四轮里一共提出 6 个 blocker 和 15 个 major，全部已修：

- 隔离逻辑打击面过大（语义校验失败的完好文档被改名搬走）
- API key 指纹算法变更导致升级用户产生重复账号与重复明文副本
- pool_id 归一化没有 legacy 兼容，存量仓库全部锁死
- 429 扫描在解析失败时只前进 1 字节，子进程可伪造限流（两次：第二轮修一次，第三轮
  新增的 `object_start_kind` 预判定又打开一次，第四轮由验收方修掉）
- `pull` 在「同一次既有 import、又有凭据已缺失的删除」时硬失败
- takeover 事务在崩溃前滚窗口里销毁用户仅存的凭据备份

### 验收依据

门禁（`ANTIGRAVITY_CONFIG_DIR` / `GEMINI_HOME` 指向沙箱）：

```text
cargo fmt --check                        CLEAN
cargo clippy --all-targets -- -D warnings CLEAN
cargo test --all-targets                 20 个二进制 / 476 个测试 / 0 失败
```

黑盒验收脚本（`backlog/verify/`，全部离线可判定、真实二进制 + 隔离 HOME + 假 agy）：

| 脚本 | 覆盖 | 修复前 | 修复后 |
| :--- | :--- | :--- | :--- |
| `t1-state-root.sh` | ROOT-001 / ROOT-002 / 旧权限迁移 | 6/18 | **18/18** |
| `t2-migration.sh` | MIG-001 | 2/6 | **6/6** |
| `t4-repo-sync.sh` | SYNC-101 / pool 归一化 / 删除传播 | 4/13 | **14/14** |
| `t6-offline.sh` | AVAIL-001 | 1/5 | **5/5** |
| `t7-cli.sh` | 死 flag / 真实 help / `-m` 等价 | 5/11 | **11/11** |
| `t10-sync-commit.sh` | pull 协同提交的坏账号场景 | 5/8 | **8/8** |
| `t11-first-run.sh` | HOME-002 | 2/10 | **10/10** |

`backlog/verify/bugs-*.sh`（tasks-v2 遗留）中 7 个仍 FAIL，逐个核实**全部是脚本自身过期**：

- `bugs-013` / `bugs-015`：把探测端点指向不可达地址后 15/15、7/7 全 PASS。
  线上失败是因为脚本用伪造 JWT，真实探测正确地拒绝了它。
- `bugs-005` / `bugs-006` / `bugs-014`：断言的 `last_synced_at` 字段在 v2 state 里已不存在；
  `is_in_cooldown` 被当作"应删除的死代码"断言，但它现在是 `src/core/policy.rs:64` 的活代码。
- `bugs-008` / `bugs-011`：纯 grep 断言指向重构前的函数名与代码形状。
  `StrictHostKeyChecking=no` 的生产分支仍然只有唯一一处，多出的匹配是新增单测。
- `bugs-002`：fixture 用的 `{"token","refresh_token","email"}` 信封已被 AUTH-005 的最小字段校验拒绝。

### 已知残留（均为 minor，不阻断发布）

- **崩溃前滚窗口无端到端覆盖**：`active_home.rs` 的 published -> finalize 前滚分支现在按 journal
  里记录的真实 mode 前滚（修复本身正确），但只有 mode 映射的单元测试；构造"State 已提交、
  finalize 未执行"的磁盘现场需要同时伪造 state 文档与 journal 的 base digest，未做。
- `--takeover` 下每次切换都留一份备份，明文副本无界累积，且不在任何清理路径里。
- 账号表格仍原样打印 email，未走 ASCII 转义（其余控制台出口已统一）。
- legacy pool id 等价类不含 scp 绝对路径写法 `git@host:/abs/path`。
- 若 active home 里的凭据属于**另一个**已登记账号，拒绝信息措辞是"不属于任何 sagy 账号"，
  会把用户引向 `--takeover` 去覆盖自己的凭据（行为仍 fail-closed）。
- 真实 429 只要伴随任意一份 401/403 形态文档，就会按"认证失效优先"丢失自动 fallback。
  这是刻意的取舍（更需要用户介入的结论优先），但代价未被测试固定。

### 需要操作者确认的一条

`src/core/credential.rs:665` 要求 authorized-user 文档同时具备
`client_id` / `client_secret` / `refresh_token` / `token_uri`。gcloud 写出的 ADC 文件通常不含
`token_uri`。该约束是 `ec18dfc` 基线自带的，不是这四轮引入的，但需要拿真实的
`~/.gemini/oauth_creds.json` 核对一次，否则 `sagy import-auth` 可能拒绝真实凭据文件。
