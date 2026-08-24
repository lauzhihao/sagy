# sagy 全库代码审查报告（2026-08-24）

## 审查基线

- 基线提交：`584ec53316b3a31586a96b48f1579aa3ed0aaf6e`
- 审查范围：Rust CLI、Antigravity adapter、账号状态与存储、usage/policy、加密账号池同步、自更新、安装脚本、release workflow、现有测试与验收脚本
- 审查方式：静态调用链审查、隔离 `HOME`/`SAGY_HOME` 的 fake `agy` 复现、本地 bare Git 仓库 round-trip、构建与测试门禁
- 本轮性质：只读审查；没有修改产品实现
- 发布结论：**BLOCKED**。修复 P0 和 P1 前，不应发布 release，也不应使用真实账号池执行 `push`、`pull` 或 `update`。

## 严重级别

- **P0**：可能导致任意命令执行、越界覆盖/删除文件，或使安装完整性校验失效；必须立即阻断发布。
- **P1**：核心功能不可用、凭据错用/丢失、状态静默丢失、跨平台主路径失效；必须在 release 前修复。
- **P2**：明确的正确性、可用性、恢复性或测试覆盖问题；应在首个稳定版本前修复。
- **P3**：低风险行为偏差、可维护性或后续增强项。

## P0：发布阻断问题

### SEC-001：SSH identity path 可形成 shell command injection

- 位置：`src/adapters/antigravity/repo_sync.rs:410-418`
- 根因：`GIT_SSH_COMMAND` 使用字符串直接拼接 `identity_file`，Git 会通过 shell 解释该字符串，路径没有 shell quoting。
- 触发：`-i` 路径包含 `;`、空格或其他 shell metacharacter。
- 影响：可执行任意本地命令；普通含空格路径也会导致 SSH 认证失败。
- 证据：隔离复现中，形如 `id;touch marker` 的 identity path 成功创建 marker 文件。
- 验收：不得以未转义字符串拼装 SSH command；含空格与 metacharacter 的路径只能被当作单个路径参数，不能执行额外命令。

### SEC-002：Repo Sync 与 account ID 缺少路径边界，可越界写入或删除

- 位置：
  - `src/adapters/antigravity/repo_sync.rs:91-102, 100-131, 194-206, 224-232`
  - `src/adapters/antigravity/paths.rs:79-80`
  - `src/adapters/antigravity/account.rs:370-373`
  - `src/core/storage.rs:229-255`
- 根因：`--path` 和 `account.id` 直接参与 `PathBuf::join`，没有拒绝绝对路径、`..`、空值、路径分隔符或 symlink。
- 触发：
  - `sagy push --path /absolute/path ...`
  - 远端 checkout 中的 `bundle.enc.json` 是指向外部文件的 symlink
  - state 或 bundle 中存在 `..`、绝对路径等恶意账号 ID
- 影响：可覆盖 checkout/state 之外的文件；`sagy rm` 遇到账号 ID `..` 时可递归删除整个 state 目录。
- 证据：隔离复现已确认绝对 `--path` 越界写入、远端 symlink 覆盖 victim、绝对账号 ID 写出 `accounts/`，以及账号 ID `..` 删除 state 目录。
- 验收：所有路径在写入/删除前 canonicalize 并验证仍位于允许根目录；拒绝 symlink target、绝对路径、`..`、空 ID 和非安全文件名 ID。

### SUPPLY-001：checksum 校验 fail-open

- 位置：
  - `src/core/update.rs:190-225`
  - `install.sh:93-113`
  - `install.ps1:36-50`
- 根因：checksum 下载失败、HTTP 非 2xx、内容为空、目标条目缺失或无本地 hash 工具时继续安装；PowerShell 连 checksum mismatch 的 `throw` 都被同一层 `catch` 吞掉。
- 影响：下载损坏或被替换的 archive 后仍可能安装/自替换，`SHA256SUMS.txt` 只形成表面校验。
- 验收：checksum 404、timeout、空文件、格式错误、缺少目标条目、不匹配、缺少 hash 工具均必须 fail-closed，且不得替换 binary。

## P1：核心功能与安全问题

### AUTH-001：Vertex 账号可导入但不可启动

- 位置：`src/adapters/antigravity/account.rs:220-245`、`auth.rs:73-79`、`launcher.rs:28-34`
- 根因：Vertex `switch_account()` 是空分支，launcher 没有设置 `GOOGLE_APPLICATION_CREDENTIALS=account.auth_path`。
- 影响：账号显示 `Ready`，子进程实际没有 service-account 凭据；若父环境已有该变量，还可能使用错误账号。
- 验收：fake `agy` 必须观察到正确且隔离的 credentials path/project；不得继承其他账号的认证环境。

### AUTH-002：OAuth JSON/raw token/API key/Vertex 切换会发生凭据污染

- 位置：`src/adapters/antigravity/auth.rs:35-80`、`launcher.rs:26-34`、`account.rs:211-258`
- 根因：
  - child process 默认继承父进程的 `GEMINI_API_KEY`、`GOOGLE_APPLICATION_CREDENTIALS`、`GOOGLE_CLOUD_PROJECT`
  - OAuth JSON 与 raw token 互切时不会删除或失效另一套 active credential
  - state normalization 会把含 access token 的 OAuth JSON `auth_path` 改成 token 文件
- 影响：启动时可能使用上一个账号或父 shell 的凭据；refresh material 与 active credential 不一致。
- 证据：隔离 fake `agy` 已观察到 OAuth 启动继承父环境；账号互切后 active OAuth JSON/token 仍属于旧账号。
- 验收：四种账号类型建立完整切换矩阵；每次切换必须显式设置/移除互斥 env 和文件，不允许上一账号残留参与认证。

### AUTH-003：更新 access token 会丢失 refresh token

- 位置：`src/adapters/antigravity/account.rs:288-355`
- 根因：按 email/fingerprint 更新现有账号时，新 `AccountRecord` 固定写入 `refresh_token: None`。
- 影响：access token 到期后无法刷新，只能重新登录。
- 验收：同账号 token 更新不得丢失仍有效的 refresh material；需覆盖重启后的 round-trip。

### AUTH-004：删除账号会谎报成功，active credential 还会被重新导入

- 位置：`src/adapters/antigravity/account.rs:370-380`、`src/cli/mod.rs:299-333`
- 根因：`remove_dir_all` 错误被忽略；只删除 state 账号目录，不处理当前生效的 Gemini/Antigravity credential。
- 影响：命令输出成功但 secret 仍在磁盘；下一次 `import-known` 可能重新加入该账号。
- 验收：删除失败必须返回非 0；删除当前账号时需定义 active credential 的一致性策略，并验证不会静默复活。

### SYNC-001：OAuth/Vertex push -> fresh pull 无法保真恢复

- 位置：`src/adapters/antigravity/repo_sync.rs:35-39, 120-128, 224-262`
- 根因：bundle 只序列化扁平的 `AccountRecord`，不包含完整 credential payload。
- 影响：
  - OAuth 丢失 `client_id`、`client_secret`、`token_uri` 等刷新字段
  - Vertex/service-account 私钥完全丢失
  - fresh pull 后账号可能存在于 state，但不能认证
- 证据：本地 bare repo round-trip 后只恢复 token 文件，没有原始 OAuth/Vertex `credentials.json`。
- 验收：token、authorized-user OAuth JSON、API key、Vertex 四类凭据均须通过 push -> 全新目录 pull -> launch -> 再 push 的保真测试。

### SYNC-002：pull 吞掉 credential 写入错误且不是事务性的

- 位置：`src/adapters/antigravity/repo_sync.rs:220-285, 239-259`
- 根因：secret write 使用 `let _ =`；账号逐个写入，没有 staging/commit/rollback。
- 影响：pull 报成功但 credential 文件缺失；中途失败会留下 orphan credential 或部分 state。
- 验收：任一账号校验/写入失败时整体不提交；错误必须传播；成功时 state 与 credential 文件同时可见。

### SYNC-003：Repo URL credential 明文持久化并可能出现在错误日志

- 位置：`src/cli/repo_sync.rs:11-16`、`src/adapters/antigravity/repo_sync.rs:421-427`
- 根因：含 `user:token@host` 的 URL 原样写入 `repo-sync.json`，Git 错误也打印完整 args。
- 影响：token 可能落在权限为 `0644` 的配置或终端日志中。
- 验收：保存和显示前统一脱敏；含 secret 的 URL 不得持久化；配置文件权限必须符合 secret policy。

### USAGE-001：429 自动轮换没有真实生产触发链

- 位置：`src/adapters/antigravity/usage.rs:121-132, 135-272`、`src/cli/mod.rs:200-204, 460-462`
- 根因：`mark_rate_limited` 只有单元测试调用；`agy` 非 0 退出后只探 tokeninfo/models，不观察实际模型请求的 `RESOURCE_EXHAUSTED`。
- 影响：README/ARCHITECTURE 宣称的“429 -> cooldown -> 自动切换”核心功能不可靠。
- 验收：fake `agy` 产生真实可观察的 rate-limit outcome 后，state 必须进入 cooldown，下一次 launch 必须选择另一个账号；不能依赖 8-bit exit code 表达 429。

### USAGE-002：cooldown 期间继续 probe，持续 429 会无限延长 cooldown

- 位置：`src/adapters/antigravity/usage.rs:49-58, 97-107, 156-162, 204-210`
- 根因：`in_cooldown` 强制绕过 cache 并继续请求；每次 429 都把截止时间重置为 `now + 300`。
- 影响：反复执行 `list`/`launch` 会继续打受限 endpoint，cooldown 可能永不结束。
- 验收：active cooldown 内不发普通 probe；恢复时机明确；若采用 `Retry-After`，必须有上限与测试。

### USAGE-003：probe 失败时健康状态 fail-open

- 位置：`src/adapters/antigravity/usage.rs:25-33, 136-142, 173-179, 227-234, 263-272`、`src/core/state.rs:88-103`
- 根因：timeout、5xx、OAuth 403、非法 JWT、Vertex 等失败只更新 `last_sync_error`，保留旧的 `Ready/100%`；`is_healthy()` 忽略 error/status。
- 影响：无效账号继续被选中，启动失败后也不能可靠 fallback。
- 验收：HTTP 200/401/403/429/5xx/timeout 必须有明确、可测试的健康状态迁移；未知失败不得伪装成 100% quota。

### POLICY-001：候选选择绕过健康检查，0% quota 账号仍可能入选

- 位置：`src/core/policy.rs:31-83`、`src/core/state.rs:98-101`
- 根因：完整 `is_healthy()` 只用于当前账号 stickiness；普通候选只要求 score > 0，0% quota 仍有基础分 1000。
- 影响：耗尽或失败账号会被重新选中。
- 验收：所有候选必须先通过统一 eligibility predicate；0 quota、needs relogin、active cooldown、不可恢复 stale 均不得入选。

### STATE-001：多进程 read-modify-write 会静默丢更新

- 位置：`src/core/storage.rs:83-108, 111-167`、`src/cli/mod.rs:155-160`
- 根因：atomic rename 只防止半写，没有 file lock、revision 或 compare-and-swap。
- 影响：并发 `add/login/use/refresh/rm` 时账号、current account 或 usage cache 最后写入者覆盖前一个结果。
- 验收：两个进程同时更新必须合并成功或明确返回 lock/revision conflict，不能静默丢数据。

### STATE-002：secret atomic write 有权限窗口，旧权限不会迁移

- 位置：`src/core/storage.rs:61-79, 128-159, 229-265`
- 根因：temp file 以默认 umask 创建，rename 后才 chmod；chmod 错误被忽略；已存在目录和 credential 不重新收紧权限。
- 影响：崩溃或异常路径可能留下 group/other 可读 secret；旧版本升级后宽权限仍存在。
- 验收：创建时即使用 0600/0700；权限设置失败必须中止；覆盖旧目录、异常中断、残留 temp 的迁移与清理测试。

### STATE-003：State version 没有校验或迁移

- 位置：`src/core/state.rs:113-137`、`src/core/storage.rs:102-107, 163-166`
- 根因：任意 version 都被接受，缺失 version 默认当前版本，没有 migration/unsupported-version 分支。
- 影响：新旧版本互读时未知字段和语义可能在下一次保存中静默丢失。
- 验收：冻结 schema/version policy；未知未来版本必须拒绝，旧版本必须迁移或给出可恢复错误。

### WIN-001：Windows 默认 credential 路径与重复保存均不可靠

- 位置：`src/adapters/antigravity/paths.rs:21-35, 61-77`、`src/core/storage.rs:111-146`、`install.ps1:9-11`
- 根因：credential path 只读取 `HOME`，不读取常见的 `USERPROFILE`；`fs::rename(temp, existing_target)` 在 Windows 不具备 Unix 式覆盖保证。
- 影响：登录/切换可能返回成功但没有写 active credential；第二次保存现有 state/credential 可能失败。
- 验收：在原生 Windows runner 覆盖首次/重复保存、OAuth 切换、默认 HOME、installer 和 `sagy-original`，不能只依赖 cross-compile。

### CLI-001：`--state-dir ... --version` 被改写为 launch 并执行外部程序

- 位置：`src/cli/mod.rs:71-112, 121-152`
- 根因：只在 argv 第一个参数识别 `--version`；之后的 router 把无已知 subcommand 的参数改写成 `launch -- ...`。
- 影响：本应无副作用的版本查询会导入/切换账号并启动 `agy --version`。
- 证据：实际运行 `sagy --state-dir <tmp> --version` 输出账号选择信息和 `agy` 版本，而不是 `sagy 0.1.0`。
- 验收：global flags 在合法位置行为一致；`--version`/help 永不加载 state、切换凭据或启动 subprocess。

### CLI-002：passthrough router 把 option value 误判成 sagy subcommand

- 位置：`src/cli/mod.rs:80-112`
- 根因：`find_first_subcmd` 只理解 `--state-dir` 的参数 arity，其他 option 后第一个非 `-` 字符串都被当成 subcommand。
- 影响：`sagy --prompt list` 把 `list` 识别为 sagy 命令并报 clap 错误；prompt/model 值与命令同名时不能透传。
- 验收：建立原始 argv 路由矩阵，至少覆盖 `--prompt list`、`--model custom`、`--model=custom`、裸 prompt、已知命令、`--` boundary。

### RELEASE-001：没有 PR/push CI，release tag 与 Cargo version 无一致性门禁

- 位置：`.github/workflows/release.yml:3-6`、`Cargo.toml:3`、`src/core/update.rs:78-89`
- 根因：workflow 仅在 `v*` tag 触发，且不比较 tag 与 package version。
- 影响：普通 main push 没有 fmt/clippy/test/build 门禁；`v0.2.0` 可发布仍报告 `0.1.0` 的 binary，updater 会反复认为有新版本。
- 验收：PR/main push 执行质量门禁；release 前严格校验 tag == Cargo version；原生 Windows job 覆盖 runtime 行为。

## P2：明确的正确性与恢复性问题

### CLI-003：help 路由自循环且截获 passthrough help

- 位置：`src/cli/help.rs:4-38, 126-167`
- 现象：`sagy add --help` 只提示再次执行同一条命令；`sagy launch -- --help` 被 sagy 截获，无法传给 `agy`。
- 验收：所有 sagy command 直接显示真实 clap 参数；`--` 后的 help 必须原样透传。

### CLI-004：`--model=custom` 仍注入默认模型，resume 判断误读 option value

- 位置：`src/adapters/antigravity/launcher.rs:36-50, 79-106`
- 现象：argv 同时出现默认模型和 `--model=custom`；`--model custom` 中的 `custom` 被当成 positional prompt，导致不注入预期的 `--continue`。
- 验收：正确解析 `--flag value` 与 `--flag=value`；不得把 option value 当 prompt。

### CLI-005：被 signal 终止的 `agy` 被当作成功

- 位置：`src/adapters/antigravity/launcher.rs:61-66`
- 根因：`status.code().unwrap_or(0)` 把 signal termination 的 `None` 映射为 0。
- 影响：脚本误判成功，也不会触发失败后的 health refresh。
- 验收：保留/映射 signal outcome 为非 0，并覆盖 SIGINT/SIGTERM。

### AUTH-005：credential 输入校验与去重不完整

- 位置：`src/cli/args.rs:127-147`、`src/adapters/antigravity/auth.rs:111-176`、`account.rs:16-26, 124-148`
- 问题：
  - `import-auth` 文档宣称支持 raw token，实际强制 JSON parse
  - `--token ""`、`--api-key "   "` 可创建空 credential
  - 相同 API key 每次生成新 UUID，不去重
  - 仅含 `{"type":"authorized_user"}` 或空 `client_secret` 的 JSON 也被当作有效 OAuth
- 验收：定义每种 credential 的最小必需字段；拒绝空 secret；统一 fingerprint 去重；文档与实现一致。

### AUTH-006：交互 OAuth token 明文回显，backup 长期保留旧凭据

- 位置：`src/adapters/antigravity/auth.rs:57-62, 94-99`
- 影响：token 可能进入录屏/terminal audit；`oauth_creds.json.bak` 长期保留旧 refresh token。
- 验收：secret input 关闭 terminal echo；backup 必须有明确权限、生命周期和删除策略。

### PATH-001：空环境 override 会把 credential 写入当前工作目录

- 位置：`src/adapters/antigravity/paths.rs:61-77`
- 根因：空 `ANTIGRAVITY_CONFIG_DIR`/`GEMINI_HOME` 被当作 `Path::new("")`。
- 影响：token 或 OAuth JSON 可落入项目 CWD 并被误提交。
- 验收：空/whitespace override 视为未设置或明确报错，不得解析为 CWD。

### UPDATE-001：版本比较不是 semver，`--force` 可降级

- 位置：`src/core/update.rs:53-75, 84-86`
- 问题：`1.0.0-rc.1` 会被判断为高于 `1.0.0`；malformed tag 缺少严格验证；`--force` 行为超过 help 所述的“同版本强制更新”。
- 验收：使用严格 semver；明确 prerelease/build metadata、远端旧版本、同版本和 force policy。

### UPDATE-002：损坏 state 会阻断 update 恢复路径

- 位置：`src/cli/mod.rs:155-160, 397-423`
- 根因：所有 command 在 match 前先加载 state。
- 影响：`state.json` 损坏后无法执行本来不依赖账号状态的 `update`。
- 验收：version/help/update 等恢复命令不应依赖可解析的账号 state，或提供 last-known-good/隔离损坏文件的恢复路径。

### SYNC-004：bundle 缺少 schema/rollback/size/幂等性约束

- 位置：`src/adapters/antigravity/repo_sync.rs:120-124, 216-224, 316-367`
- 问题：
  - 不验证 `bundle.version`/`exported_at`
  - 没有 ciphertext/plaintext/account count 大小上限
  - 同一 state 每次随机 salt/nonce，push 总产生新 commit
  - duplicate ID 使用 last-wins，导入计数与最终 state 不一致
- 验收：拒绝未知未来版本与非法/重复 ID；定义 rollback policy 和资源上限；相同语义数据 push 应可检测 no-op。

### SYNC-005：Git positional 参数缺少 `--`，insecure flag 行为不一致

- 位置：`src/adapters/antigravity/repo_sync.rs:133-138, 390-419`
- 问题：`--path=-A` 等可形成 Git option injection；`--insecure-host-key` 只有同时提供 `-i` 才生效。
- 验收：所有用户控制的 positional 参数前使用 `--` 或等价安全 API；insecure flag 单独使用时也应行为明确并告警。

### STATE-004：损坏 state、未来 TTL 与旧 credential 权限缺少恢复测试

- 位置：`src/core/storage.rs:102-108`、`src/adapters/antigravity/usage.rs:48-54`
- 问题：损坏 JSON 没有 last-known-good；未来 `last_synced_at` 可让 cache 长期有效；旧 credential mode 不迁移。
- 验收：覆盖损坏/截断 state、未来时间戳、时钟回拨、旧权限升级和 temp 残留。

## 测试与验收现状

以下门禁在审查基线上均通过：

- `cargo fmt --check`
- `cargo check --all-targets`
- `cargo test --all-targets`：23 passed
- `cargo clippy --all-targets -- -D warnings`
- `backlog/verify/bugs-001.sh` 至现有全部 12 个验收脚本：全部 PASS

这些绿色结果不能证明 release 可用：

- `backlog/verify/bugs-005.sh` 只检查失败后 `last_synced_at` 是否变化，没有断言真实 429、cooldown 或 fallback。
- `backlog/verify/bugs-008.sh` 只 grep `SHA256SUMS`、`Sha256` 等源码字面，没有模拟 checksum 404、缺条目或 mismatch。
- 现有单元测试没有覆盖 CLI -> adapter -> filesystem -> subprocess 的完整边界。
- 没有原生 Windows runtime test。
- 没有 OAuth JSON/Vertex repo round-trip、路径逃逸、symlink、并发写 state、HTTP 状态矩阵测试。

## Release 解锁门禁

按以下顺序处理，避免在未固定公共边界时反复返工：

1. 立即修复或临时禁用 Repo Sync 的 command/path trust boundary，以及 updater/installers 的 fail-open checksum。
2. 冻结 portable credential schema、account ID invariant、State migration/transaction policy、launcher outcome 接口。
3. 修复 storage 的锁/事务、创建时权限、旧权限迁移和 Windows replace 行为。
4. 完成 OAuth/API key/Vertex 四类凭据隔离切换，以及 repo push/pull 保真 round-trip。
5. 建立可达的 rate-limit outcome，修复 cooldown/probe/policy 状态机。
6. 修复 CLI router/help/version/signal 行为。
7. 增加 PR/main CI、tag-version gate、原生 Windows job 和上述端到端验收。

只有 P0/P1 全部关闭、相关回归测试 fail-before/pass-after、且真实凭据路径始终被隔离后，才允许解除 **BLOCKED**。
