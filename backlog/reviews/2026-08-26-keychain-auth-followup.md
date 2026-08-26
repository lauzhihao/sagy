# sagy Keychain 认证边界跟进（2026-08-26）

## 结论

`sagy say hi` 的 argv bug 已修复：开头的裸 prompt 现在变成 `agy -p "say hi"`，不再与隐式
`--continue` 组合。本地 release 已在真实用户 HOME/Keychain 下返回 `Hi! How can I help you
today?`，退出码 0，真实两份 credential file 的 digest 未变化。

进一步实测确认，当前 `agy` 的有效认证权威高置信位于操作系统 credential store，而不是可通过
复制 `~/.gemini` 携带的两个文件。此前把两个 provider 文件建模为独立、可 repo 同步、可切换账号
的四个本地提交已经用 additive `git revert` 撤回，未 push、未打 tag、未发布。

## 证据

- zsh alias 与直接命令最终均使用 `/Users/liuzhihao/.local/bin/agy`；绕过 alias 后真实 HOME 下
  `agy -p "say hi"` 仍成功，排除二进制和 alias 参数差异。
- `agy` 链接 macOS `Security.framework` 与 `go-keyring`，本机存在 service=`gemini` 的 Keychain
  item；未读取 item value。
- 二进制包含 system keyring 恢复、timeout 后 fallback 到 file storage、无 controlling terminal
  时不能交互登录等明确路径。
- 磁盘 `oauth_creds.json` 的 access expiry 已过期，真实 HOME 成功调用前后仍未改写。
- 完整复制 `~/.gemini`，以及追加复制 Antigravity desktop 目录，均不能让自定义 HOME 的新进程
  免登录；保留权限与 mtime 后结论不变。
- 用户历史上的合盖后台保活现象与 vault 不可用/timeout 后 fallback 完全一致：定时任务反复进入
  OAuth，叠加出多个登录流程。

## 安全决策

- 不直接 CRUD provider 的 Keychain item，不读取 secret，不复制 login keychain，不执行
  `security ... -w`。
- strict six-field provider session 进入 `import-known` 时 fail-closed：state 与 active-home 不变，
  不 spawn `agy`，提示当前 session 可能由 system credential store 管理并建议直接运行 `agy`。
- 旧 Google `authorized_user`、用户显式 raw token、API key 与 Vertex 行为保持不变。
- 后续只有取得 provider 支持的非交互 auth status、file-token-store override、有效身份确认和
  no-browser-login 契约，才能设计 local-only provider session；不得进入 repo sync，也不得仅凭
  `say hi` 声称账号切换成功。

## 真实 smoke 的隔离方式

最终 smoke 保留真实 `HOME=/Users/liuzhihao` 以允许 `agy` 访问当前 Keychain，同时把
`SAGY_HOME`、`GEMINI_HOME`、`ANTIGRAVITY_CONFIG_DIR` 与 `--state-dir` 全部指向一次性目录。
临时目录中的两份 fixture 与真实源逐字节一致，运行后确认：

```text
sagy selected account                         PASS
agy returned a greeting                       PASS
process exit code                             0
real credential file digests                  unchanged
temporary credential/state directory          removed
```

该 smoke 证明 argv 与当前系统 session 可用，不证明 OAuth 多账号切换已生效；后者在 provider
提供身份 postcondition 之前明确不作承诺。

## 最终本地验收

所有 Cargo 命令均预先设置 `ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary` 与
`GEMINI_HOME=/tmp/sagy-canary`：

```text
cargo fmt --all -- --check                              PASS
cargo check --all-targets --locked                      PASS
cargo clippy --all-targets --locked -- -D warnings      PASS
cargo test --all-targets --locked                       24 个 executable / 496 项 / 0 失败
p1_provider_managed_session                             3/3 PASS
p1_bare_prompt                                          5/5 PASS
backlog/verify/t*.sh                                     7 个脚本 / 72 项断言 / 全部 PASS
```

本轮只创建本地提交，不执行 push、tag 或 release。发布前仍需 exact commit 的 Linux quality 与
原生 Windows runner 证据。
