# sagy

[English](./README.md) | [简体中文](./README.zh-CN.md)

`sagy` 是一个基于 Rust 开发的 Google Antigravity CLI (`agy`) 智能多账号管理与环境包装启动器。它支持多账号自动优选轮换、429 限流冷却降级以及基于 Git 的多机加密账号池同步。

这个仓库只包含纯开源代码，不包含任何个人账号数据、凭据或私有环境文件。

---

## 一、安装

> 当前尚未发布 GitHub Release。在首个 release 产生之前，一键安装脚本和 `sagy update`
> 无法下载二进制；目前请使用下方的源码编译方式。

### Unix (macOS / Linux):

```bash
curl -fsSL https://raw.githubusercontent.com/lauzhihao/sagy/main/install.sh | bash
```

### Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/lauzhihao/sagy/main/install.ps1 | iex
```

### 预编译支持平台：

- macOS：`aarch64-apple-darwin` (Apple Silicon), `x86_64-apple-darwin` (Intel)
- Linux：`x86_64-unknown-linux-musl`
- Windows：`x86_64-pc-windows-msvc`

### 从源码编译：

```bash
cargo build --release
```

---

## 二、安装的二进制命令

下面的命令表针对发布版的可携带凭据入口。在 macOS 上使用本文的原生订阅安装方式时，请用 `sagy-legacy` 执行这些命令。

安装后，`sagy` 会在 `$SAGY_HOME/bin` 中提供以下便捷入口：

| 命令 | 对应模型与行为 |
| :--- | :--- |
| **`sagy`** | 默认主命令，智能优选最佳账号后启动 `agy`（默认注入 `gemini-3.7-flash-high`；切换其它模型请在 agy 界面内操作） |
| **`sagy-original`** | 到底层官方 `agy` 二进制的透明直通辅助命令 |

---

## 三、命令总览

尖括号 `<>` 表示必填参数，方括号 `[]` 表示可选参数。

| 命令 | 说明 |
| :--- | :--- |
| `sagy` / `sagy launch [agy 参数...]` | 刷新状态，优选当前最健康账号，切换环境后启动 Antigravity CLI |
| `sagy auto` | 优选并切换至最佳账号，但不启动 CLI |
| `sagy list` | 查看所有账号列表、计划类型、健康状态及冷却倒计时 |
| `sagy refresh` | 立即刷新所有账号的状态 |
| `sagy use <邮箱\|ID>` | 按邮箱或 ID 手动切换到指定账号 |
| `sagy rm <邮箱\|ID>` | 删除指定的账号凭据 |
| `sagy add` | 添加新账号凭据。凭据参数与 `login` 相同，另有 `--switch`；不给凭据参数时走交互式输入 |
| `sagy login` | 注册或更新一个账号凭据。给 `--token` / `--api-key` 即非交互；都不给时提示一次并以隐藏输入读取你手上已有的 token |
| `sagy import-known` | 自动扫描本地已有的 `~/.gemini` 凭据并导入 |
| `sagy import-auth <路径>` | 从指定的 JSON 凭据或 Token 文件导入账号 |
| `sagy push [仓库]` | 使用 `SAGY_POOL_KEY` 强加密 (XChaCha20Poly1305) 推送账号池至 Git 仓库 |
| `sagy pull [仓库]` | 从 Git 仓库拉取并解密同步账号池到本地 |
| `sagy update` | 从 GitHub Releases 检查并自动升级二进制（别名：`sagy upgrade`） |
| `sagy -- <agy 参数...>` | 把 `--` 之后的全部参数原样透传给 `agy` |

第一个 token 只要不是已知子命令，同样会被整体透传给 `agy`。
若透传内容以裸 positional 单词开头，sagy 会把第一个 option 之前的连续单词合成一个显式
print prompt：`sagy say hi` 实际启动 `agy -p "say hi"`。后续 option 仍按原顺序逐项透传。

### `login` / `add` 如何取得凭据

`sagy login` 与 `sagy add` 不会打开浏览器，也不会执行任何 OAuth 授权流程。所有模式都只是**接收**
你已经持有的凭据：

- `--token <TOKEN>` / `--api-key <KEY>`：完全非交互。
- 不给凭据参数（或显式 `--oauth`）：打印
  `Paste your Antigravity OAuth Token (or Google Token):`，然后关闭回显读取一行。
  没有浏览器跳转，没有 authorization code，也没有 `client_id` / `client_secret` 交换。

sagy 同样不会拿 `refresh_token` 去换新的 access token。`authorized_user` 文档里的 `refresh_token`
只被原样保存、同步并交给 `agy`，真正的刷新由 `agy` 自己向 Google 发起。探测发现 authorized_user
凭据过期时，sagy 只把账号标记为"需要刷新"，不会代为刷新。

新版 `agy` 可以把真正生效的登录态保存在操作系统 credential store（macOS Keychain 及其它平台
对应的系统 vault）中。因此，`~/.gemini/oauth_creds.json` 里的严格六字段 provider session 不会
被当作可携带、可独立切换的账号：`import-known` 会 fail-closed，不改文件，也不启动 `agy`。
在 macOS 上，如果 sagy 账号池为空、请求又是非交互 print prompt，sagy 可以把这一次请求交给
当前本机 `agy` session。启动前只检查 Keychain 状态和 provider item 元数据，不请求 secret，并且
整个检查有时限、禁止 UI；Keychain 被锁、缺失、不可用或超时都会在 spawn `agy` 前退出。这条
local-only 路径不会被导入、切换或 repo sync。

Keychain 检查与 child spawn 无法成为原子操作，因为 `agy` 没有公开受支持的“绝不发起授权”开关。
sagy 还会监督 child；一旦识别到 provider 授权流程，就 kill 整个 child process group，避免残留
等待登录的进程。第二道保护是竞态遏制，不承诺极窄的检查后竞态中浏览器绝不会短暂出现。

Google `authorized_user` JSON 必须包含 `client_id`、`client_secret` 与 `refresh_token`。
`token_uri` 可以省略；sagy 会在内部将其规范化为
`https://oauth2.googleapis.com/token`。如果显式提供了其它 endpoint，则按 fail-closed
原则拒绝。active home 中导入的原始字节保持不变，portable 与 repo-sync 序列化使用规范 endpoint。

若 timeout、DNS 失败、连接拒绝、代理失败或网关失败仅说明探测通道不可达，且凭据已在本地校验，
该账号仍可在最低的 `Degraded` 等级参与选择；服务端明确拒绝凭据时仍不可选。

### macOS 上切换个人订阅账号

在项目根目录运行安装脚本，会编译一份 Rust 程序。`sagy` 和 `sagy-profile` 使用原生订阅账号池，`sagy-legacy` 提供原有可携带凭据命令。后续更新也使用同一安装脚本。已有 profile 会继续使用原目录和登录态，下面的 `login` 仅用于新增账号。每次授权时核对浏览器显示的 Google 邮箱，回到终端按 `agy` 的提示完成，进入会话后输入 `/exit` 退出。

```bash
./scripts/install-profiles.sh
sagy-profile login work@example.com
sagy-profile login personal@example.com
```

将同一启动器以可执行文件名 `sagy` 安装后，单独运行 `sagy` 等同于 `sagy-profile auto --model gemini-3.8-flash-high --dangerously-skip-permissions`。`sagy -p "提示词"` 使用相同默认配置执行一次非交互请求。子命令原样交给 profile 命令，例如 `sagy login work@example.com`、`sagy list`。

自动化可以写 `sagy --print "提示词"`，也可以把选项放在提示词之前，例如 `sagy --output-format json -p "提示词"`。用 `sagy help 命令` 或 `sagy 命令 --help` 查看该命令的参数，用 `sagy --version` 查看启动器版本。

`sagy rm work@example.com` 按准确标签（或邮箱）移出本机账号池，并显示私有归档路径。归档中保留该账号的登录凭据和对话。正在使用的账号需要先退出会话。纯数字按标签处理；列表序号只用于 `use`。如果远端仓库还有该标签，再次 `pull` 会重新导入它。

额度查询和模型请求沿用调用方的代理环境变量。若未设置 HTTP、HTTPS 或 ALL 代理，则默认使用 `http://127.0.0.1:10808`；已有的 `NO_PROXY` 规则仍生效。

`sagy-profile auto` 在启动前向每个空闲账号查询原生 `/usage`。默认比较 Gemini 组，显式指定 `--model claude-sonnet-4-6` 或 GPT 模型时比较 Claude/GPT 组。每个账号以 5 小时和每周两个窗口中较低的剩余百分比参与排序，同分时轮换。查不到额度的账号作为备选，确认耗尽、正在冷却或所选模型组周额度低于 5% 的账号会被跳过；周额度恰好 5% 仍可选。用 `sagy use work@example.com` 可指定账号打开新实例，默认 Gemini 3.8 Flash High 和最高权限，不自动续接；也可追加 agy 参数。`sagy use 1` 按执行时本地快照的列表顺序打开第一个账号，序号从 1 开始；额度更新后排序可能改变，可先运行 `sagy list` 确认。纯数字参数优先作为序号，纯数字标签仍可用 `sagy run 标签` 启动。周额度门槛仅用于自动选号，`use` 允许手动指定低额度账号。用 `sagy-profile run work@example.com` 可原样启动某个账号，在第二个终端用 `sagy-profile run personal@example.com` 可同时使用另一个账号。`sagy-profile list` 列出本地标签。账号被撤销授权时，重新运行对应的 `login`。

`sagy list` 只读取本地 `~/.local/share/sagy-profiles/quota.json` 中的 Gemini 额度快照，不发起网络查询。表格的 `Quota age` 显示采样距今多久；没有快照时显示 `--`。快照是 agy 最近报告的额度，在其他客户端使用账号或服务端数据尚未同步时可能滞后。查询失败时保留上次成功值及其原始时间。

交互会话通过 agy 原生 `statusLine` 状态回调检测每轮回复完成，然后在独立临时 HOME 中后台查询 Gemini 额度并更新快照，无需退出会话。查询使用当前登录凭据的临时副本，不写回运行中会话的凭据，完成后清理；每个会话至多一个查询在运行，连续结束的轮次会合并刷新。已有自定义状态栏命令仍接收原始输入并保留输出；覆盖仅对本次会话生效，不改写设置文件。重复的界面刷新不会触发重复查询。已打开的旧会话需要重启一次 `sagy` 才能接入；会话内主动修改 `/statusline` 可能替换此回调。后台查询最多等待 25 秒，成功后快照才更新，因此会比回复完成晚几秒；失败时继续显示上次结果及其时间。

启动器内置更新 hook：登录成功、`run` 或 `auto` 会话正常退出时，查询并更新该账号的 Gemini 快照，退出阶段最多额外等待 8 秒；信号退出会跳过。`auto` 启动前的 Gemini 实时查询也会更新快照。更新失败不会改变会话退出码。需要立即更新或接入自己的 hook 时可调用：

```bash
sagy refresh                    # 并行刷新所有空闲账号
sagy refresh work@example.com   # 只刷新指定账号
sagy refresh --strict work@example.com  # 本次获取两个额度窗口才成功
sagy list                       # 读取快照，不等待网络
```

`refresh` 每个账号最多等待 25 秒，忙碌账号会跳过。`auto` 仍按实时查询结果选择账号，不依赖列表快照。设置 `SAGY_PROFILE_ROOT` 时，快照跟随该目录保存。

这个入口适用于已验证的 macOS arm64 版 `agy 1.4.12`，会校验可执行文件摘要。它让每个进程使用独立的 `HOME`，由 `agy` 的 SSH 登录模式自行保存和刷新凭据。默认目录为 `~/.local/share/sagy-profiles`。工作目录沿用当前项目，对话、设置以及依赖 `~` 的工具配置则按 profile 隔离。在终端用裸 `auto` 或仅带模型、effort 选项启动时，若本次进程日志报告原生模型执行 429，当前账号会冷却 5 分钟。有空闲备号时自动打开新的交互会话；没有备号时留在当前会话。原账号的历史和未完成任务留在原处。`-p`、管道输入、显式续接或指定对话等调用只记录冷却，以免重复执行工作。

### 同步原生订阅账号

原生入口的 `sagy push` / `sagy pull` 同步当前 `sagy list` 中的订阅账号。设置 `SAGY_POOL_KEY` 作为加密口令，所有参与同步的机器使用相同口令。首次指定账号仓库地址，后续可以省略，也可通过 `SAGY_POOL_REPO` 提供地址：

```bash
sagy push git@github.com:you/private-sagy-accounts.git
sagy pull git@github.com:you/private-sagy-accounts.git
# 记住仓库地址后
sagy push
sagy pull
```

账号仓库中仅写入 `.sagy-native-profiles/bundle.enc.json` 密文，使用 Argon2id 和 XChaCha20-Poly1305。同步内容是账号标签和 agy 的完整登录凭据，不包含本机目录、聊天记录、设置或额度快照。口令不会保存到仓库，也不会传给 agy 或 Git 子进程。`--path` 可指定仓库中的相对目录，`-i` 可指定 SSH 私钥；这些选项需要在调用时提供。

`push` 合并本地和远端账号，保留远端独有账号；同标签对应不同登录凭据时拒绝推送，避免替换另一份登录态。正在使用的账号会导致导出明确失败，退出对应会话后再推送。`pull` 只导入本机缺少的标签，已有同名账号保留并显示跳过，不覆盖当前登录文件或删除账号。拉取完成后可运行 `sagy refresh` 获取额度；只要原登录仍有效，就无需再次登录。

这个格式与旧账号池分开存放。`sagy-legacy push/pull` 继续使用旧版可携带凭据协议；原生入口不会把旧格式误当作订阅账号导入。

### 会话续接规则

`sagy` 与 `sagy launch` 会向 `agy` 的 argv 追加 `--continue`，因此默认续接上一轮会话。
开头的裸 prompt 会先被规范化：第一个 option 之前的连续 positional 单词会合成一个 `-p` 值，
因此 `sagy say hi` 会开启新的 print turn，不会再收到隐式 `--continue`。除此以外，只有两种情况
会关闭续接：

1. `--no-resume`。它属于 sagy 侧参数，必须写在第一个 `agy` 参数之前
   （`sagy --no-resume ...` 或 `sagy launch --no-resume ...`）。写在 `agy` 参数之后就不再是
   sagy 参数：`sagy --yolo --no-resume` 会把 `--no-resume` 原样透传给 `agy`，续接照旧生效。
2. 传给 `agy` 的参数本身已经承载了会话意图。此时 sagy 不再叠加，交给 `agy` 自己决定。
   触发条件为出现以下任意一项：
   `-c`、`--continue`、`-p`、`--print`、`--print=<...>`、`--prompt`、`--prompt=<...>`、
   `-i`、`--prompt-interactive`、`--conversation`、`--conversation=<...>`、
   任何不以 `-` 开头的裸 positional token，或**本身仍留在交给 `agy` 的参数列表里**的 `--`
   分隔符（该分隔符之后的内容同样计入）。
   `--model` / `-m` 后面跟的值属于 option value，不算裸 token。

   开头的那个分隔符会被 sagy 自己的参数解析吃掉，根本到不了这项判定：
   `sagy -- --help` 与 `sagy launch -- --help` 实际只按 `--help` 判定，因此仍会续接会话，
   要开新会话请显式加 `--no-resume`。写在中间的分隔符（例如 `sagy --yolo -- --help`）
   会原样传给 `agy`，这时才会关闭续接。

纯透传（`sagy <agy 参数...>`）遵循同一条规则：只有 `--no-resume` 能关闭续接，
多带一个与会话无关的 flag 不会悄悄改变续接行为。

### 参数

| 作用范围 | 参数 | 含义 |
| :--- | :--- | :--- |
| 全局 | `--state-dir <路径>` | 本次调用覆盖 state 根目录（优先级高于 `SAGY_HOME`） |
| `launch` | `--dry-run` | 只预览优选结果，不切换也不启动 |
| `launch` | `--no-launch` | 切换到最佳账号后退出，不启动 CLI |
| `launch` | `--no-resume` | 不续接上一轮会话。必须写在第一个 `agy` 参数之前 |
| `launch` | `--no-import-known` | 跳过对本地 `~/.gemini` 凭据的自动发现与导入 |
| `launch` | `--takeover` | **覆盖 active home 里 sagy 不认识的凭据**，说明见下方「安全逃生口」 |
| `auto` | `--dry-run`、`--no-import-known`、`--takeover` | 含义同 `launch` |
| `use` | `--takeover` | 含义同 `launch` |
| `add` | `--switch` | 添加完成后立即切换到该账号 |
| `add`、`login` | `--token <TOKEN>` | 原始 OAuth / Antigravity token |
| `add`、`login` | `--api-key <KEY>` | Google Gemini API Key |
| `add`、`login` | `--oauth` | 显式选择交互式 token 输入（不给任何凭据参数时本就是默认行为）。与 `--token` / `--api-key` / `--api` 互斥 |
| `add`、`login` | `--api` | 接收但不生效：与 `--api-key` 同时给时不改变任何行为，单独给则只能报 `When using --api, please also provide --api-key <KEY>`。已废弃，直接用 `--api-key` |
| `add`、`login` | `--email <邮箱>` | 账号关联的邮箱地址 |
| `add`、`login` | `--project-id <ID>` | Google Cloud 项目 ID（可选） |
| `add`、`login` | `--takeover` | 含义同 `launch` |
| `rm` | `-y`、`--yes` | 跳过删除确认 |
| `update` | `-f`、`--force` | 版本相同也强制更新 |
| `push`、`pull` | `--path <仓库内路径>` | 仓库内存储目录（默认 `.sagy-account-pool`） |
| `push`、`pull` | `-i <密钥文件>` | 用于仓库认证的 SSH 私钥路径 |
| `push`、`pull` | `--insecure-host-key` | **关闭 SSH host key 校验**，风险说明见第四节 |

### 安全逃生口：`--takeover`

sagy 绝不静默覆盖不是自己写的凭据。它在 active home 里纳管的只有两个文件：
`$ANTIGRAVITY_CONFIG_DIR/antigravity-oauth-token` 与 `$GEMINI_HOME/oauth_creds.json`。

两种情况被区别对待，只有第二种需要你动手：

严格六字段 provider-managed session 会先于这两种情况处理：sagy 不接管也不覆盖它，因为真正的
secret 可能只存在于操作系统 credential store。`import-known` 与账号切换命令会以明确的
unsupported-session 错误停止；符合上述条件的 macOS print launch 可以改走受保护的 local-only
passthrough。

1. 文件里的内容**就是**某个已登记账号的凭据（逐字节一致）：sagy 就地接管，一个字节都不改写。
   已经在用 Antigravity 的机器上第一次跑 `sagy` 属于这一类，不需要任何参数。
2. 文件是 sagy 不认识的：本次切换被拒绝，磁盘不做任何改动，错误信息里会直接给出下面这条命令。

`--takeover` 就是第二种情况的显式 opt-in。它在写入所选账号之前，把每个被替换掉的文件
改名成**同目录下**的 `<原文件名>.sagy-backup-<txid>`，因此被替换掉的凭据永远可恢复：

```bash
sagy launch --takeover
```

`sagy auto`、`sagy use`、`sagy login`、`sagy add` 上都有同名参数。你也可以自己先把这两个文件
备份走再删掉，sagy 就会从一个空的 active home 开始。

---

## 四、加密账号池跨机同步

在多台机器（例如 Mac 工作站与远程 Linux 服务器）之间同步账号池：

1. 设置加密密钥（两端保持一致）：
   ```bash
   export SAGY_POOL_KEY="your-strong-secret-key"
   ```
2. 推送本地账号池：
   ```bash
   sagy push git@github.com:your-username/my-sagy-pool.git
   ```
3. 在另一台机器下拉取并解密导入：
   ```bash
   sagy pull git@github.com:your-username/my-sagy-pool.git
   ```

bundle 使用 XChaCha20Poly1305 加密、Argon2id 派生密钥，落在
`<仓库>/.sagy-account-pool/bundle.enc.json`。

### 仓库来源的解析优先级

`push` / `pull` 使用的仓库按以下顺序解析，命中即止：

1. 位置参数 `[仓库]`。给了就同时写回 `repo-sync.json`。
2. 之前的运行写进 `$SAGY_HOME/repo-sync.json` 的 `last_repo`。
3. 环境变量 `SAGY_POOL_REPO`。

三者都没有时命令直接报错，要求补一个仓库地址。
注意：已保存的 `repo-sync.json` 优先级高于 `SAGY_POOL_REPO`。

### 安全逃生口：`--insecure-host-key`

host key 校验**默认开启**：sagy 不会削弱 SSH 的默认行为，遇到未知或变更的 host key 会直接中止传输。

`--insecure-host-key` 会让底层 git 以 `ssh -o StrictHostKeyChecking=no` 运行，
即无条件接受服务端出示的任意 host key。这意味着中间人可以冒充远端，
观察你每一次 push/pull 的账号池流量。bundle 本身仍由 `SAGY_POOL_KEY` 加密，
但连接不再能证明对端身份。使用该参数时命令会向 stderr 打印明确警告。

只在自己完全掌控的仓库、且处在可信网络时才用它；更好的做法是把主机加进
`~/.ssh/known_hosts`。

---

## 五、环境变量

| 变量 | 使用方 | 作用 |
| :--- | :--- | :--- |
| `SAGY_HOME` | CLI、安装脚本 | state 与安装根目录，默认 `~/.sagy`；`--state-dir` 优先级更高 |
| `SAGY_POOL_KEY` | `push`、`pull` | 账号池 bundle 的加密口令，同步必需 |
| `SAGY_POOL_REPO` | `push`、`pull` | 兜底仓库地址，仅在既无参数也无 `repo-sync.json` 记录时生效 |
| `SAGY_UPDATE_REPO` | `update` | 拉取 release 的 GitHub `owner/repo`，默认 `lauzhihao/sagy` |
| `ANTIGRAVITY_CONFIG_DIR` | CLI | 覆盖真实的 Antigravity CLI 目录，默认 `~/.gemini/antigravity-cli` |
| `GEMINI_HOME` | CLI | 覆盖真实的 Gemini 目录，默认 `~/.gemini` |
| `AGY_BIN` | `launch`、透传 | 显式指定 `agy` 二进制路径，优先于其它所有查找方式 |
| `LC_ALL`、`LC_MESSAGES`、`LANG` | CLI | locale 为 `zh*.UTF-8` 时输出中文，否则输出英文 |

仅安装脚本使用的变量：

| 变量 | 脚本 | 作用 |
| :--- | :--- | :--- |
| `SAGY_REPO` | `install.sh` | 下载来源的 GitHub `owner/repo`，默认 `lauzhihao/sagy` |
| `SAGY_VERSION` | `install.sh` | 安装指定 tag 而不是最新 release |
| `INSTALL_BIN` | `install.sh` | 二进制安装目录，默认 `$SAGY_HOME/bin` |
| `SAGY_CURL_CONNECT_TIMEOUT` | `install.sh` | curl 连接超时（秒），默认 `10` |
| `SAGY_CURL_MAX_TIME` | `install.sh` | curl 总超时（秒），默认 `120` |
| `SAGY_DOWNLOAD_TIMEOUT_SEC` | `install.ps1` | 下载超时（秒），默认 `120` |

### 传给 `agy` 子进程的环境

每次启动都会先清除下面完整的认证面，避免父 shell 或上一个账号把凭据带进来：

```text
CLOUDSDK_AUTH_ACCESS_TOKEN
CLOUDSDK_CORE_PROJECT
GEMINI_API_KEY
GOOGLE_API_KEY
GOOGLE_APPLICATION_CREDENTIALS
GOOGLE_CLOUD_ACCESS_TOKEN
GOOGLE_CLOUD_LOCATION
GOOGLE_CLOUD_PROJECT
GOOGLE_CLOUD_QUOTA_PROJECT
GOOGLE_GENAI_USE_GCA
GOOGLE_GENAI_USE_VERTEXAI
GOOGLE_OAUTH_ACCESS_TOKEN
```

随后只重建本次启动需要的值：API key 账号写入 `GEMINI_API_KEY`，Vertex service account
写入 `GOOGLE_APPLICATION_CREDENTIALS`，OAuth 或 Vertex 账号带 project ID 时写入
`GOOGLE_CLOUD_PROJECT`，父进程的 `GOOGLE_CLOUD_LOCATION` 只有通过 region 格式校验后才会写回。
清单中的其它变量保持不存在。

`ANTIGRAVITY_CONFIG_DIR` 与 `GEMINI_HOME` 同时也是开发期的凭据沙箱：跑 `cargo test`
之前必须把两者指向临时目录，否则测试会覆盖你 `~/.gemini` 里的真实凭据。

---

## 六、运行目录结构

默认状态目录位于 `~/.sagy`（可通过 `SAGY_HOME` 或 `--state-dir` 自定义）：

```text
~/.sagy/
  bin/              # 二进制文件 (sagy, sagy-original)
  accounts/         # 各独立受管账号凭据与配置
  runtime/          # 可选的本地工具链或运行时
  tmp/              # 临时解压与同步工作区
  state.json        # 本地状态清单与健康缓存
  repo-sync.json    # 上次同步仓库记录
```

---

## 七、开源协议

本项目基于 MIT 许可证开源。
