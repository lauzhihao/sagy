# sagy provider-native 凭据跟进（2026-08-26）

## 结论

本轮已修复 `sagy say hi` 的 argv 语义，并把 Antigravity/Gemini 的两个 provider-native
已知凭据源建模为互相独立、逐字节保真的 credential kind。代码、Rust 全量门禁与 72 项离线
黑盒验收均通过；未 push、未打 tag、未发布。

真实 `agy` smoke 还揭示了一个外部状态边界：当前正在运行的 `agy` 进程可以持有可用的进程内
认证状态，但磁盘上的 provider 文件可能已经过期。完整复制 `~/.gemini`，甚至连同
`~/Library/Application Support/Antigravity` 一起复制，也不能复制进程内状态。sagy 不读取或转储
其它进程内存，因此这类副本需要重新完成一次 provider OAuth 才能用于新进程 smoke。

## 已关闭问题

### 1. 裸 prompt argv

- `sagy say hi` 现在生成 `agy --model gemini-3.7-flash-high -p "say hi"`。
- 不再隐式追加 `--continue`。
- 只合并开头连续 positional run；遇到第一个 option 后不再猜测其参数归属。
- Unix 非 UTF-8 argv 字节保持不变。

### 2. Provider-native credential kind

- `antigravity-oauth-token` 作为 `AntigravityToken` 保存原始字节。
- 严格六字段 `oauth_creds.json` 作为 `GeminiOAuthSession` 保存原始字节；`id_token` 与
  `scope` 字段允许 provider 合法的空字符串。
- 两个源独立 import、独立账号、独立 active-home slot，不合并、不注入 endpoint。
- repo bundle 加密往返后仍保留精确 source bytes。
- 两类凭据的探测与刷新都委托 `agy`，sagy 不直接访问 provider endpoint。

### 3. 首次接管与轮换

- `import-known` 在同一 State CAS 中提交两个源，随后只发布被选中账号对应的 slot；另一份仍保留
  在 account store。
- `adopt_known` 已进入 state proof 与 durable journal 的合法 mode 集合。
- Gemini access token / id token / expiry 轮换但 refresh identity 不变时，重启后仍复用原账号；
  identity fingerprint 不写入明文 `state.json`。
- provider-native token 在 publish/finalize/cleanup 阶段按 staged kind 解析，避免被误判为旧式
  `OauthAccessToken`。
- 旧式 raw token 与 Google `authorized_user` 导入行为保持兼容。

## 真实运行时核对

正在运行的 `agy` 进程使用：

```text
HOME=/Users/liuzhihao
~/.gemini/antigravity-cli/{brain,crashes,knowledge,log,presence}
~/.gemini/config/projects
```

没有 `GEMINI_HOME` / `ANTIGRAVITY_CONFIG_DIR` / `JETSKI_OAUTH_TOKEN` 等认证覆盖，也没有打开
`~/Library/Application Support/Antigravity`。临时 HOME 中的新日志证明 `agy` 确实读取了复制后的
`~/.gemini`，但新进程仍要求认证；加入完整 Antigravity desktop 目录后结论不变。真实凭据文件
在测试前后 digest 未变，临时副本测试后已删除。

这说明“运行时根目录是 `~/.gemini`”与“当前进程登录态可由目录复制”是两个不同命题：前者已由
打开文件与临时日志证实，后者被真实 smoke 证伪。要获得成功的 `say hi` 响应，需要为临时副本
完成一次新的 provider OAuth；旧 PKCE authorization code 不能跨进程复用。

## 本地验收

所有 Cargo 命令均使用：

```text
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
GEMINI_HOME=/tmp/sagy-canary
```

结果：

```text
cargo fmt --all -- --check                              PASS
cargo check --all-targets --locked                      PASS
cargo clippy --all-targets --locked -- -D warnings      PASS
cargo test --all-targets --locked                       25 个 executable / 511 项 / 0 失败
backlog/verify/t*.sh                                     7 个脚本 / 72 项断言 / 全部 PASS
```

## 剩余外部证据

1. 对新的临时运行时完成一次 provider OAuth 后，执行真实 `target/release/sagy say hi` smoke。
2. push 后观察 exact commit 的 Linux quality 与原生 Windows jobs；本轮不执行 push/tag/release。
