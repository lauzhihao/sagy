# sagy Keychain 认证边界跟进（2026-08-26）

## 结论

`sagy say hi` 的 argv bug 已修复：开头的裸 prompt 现在变成 `agy -p "say hi"`，不再与隐式
`--continue` 组合。直接运行真实用户 HOME/Keychain 下的 `agy -p "say hi"` 已返回 greeting；
最终 release 构建也已通过受保护的 local-only native passthrough 返回 greeting。

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
  `security ... -w`。preflight 只用 Security.framework 检查默认 Keychain 的 unlocked/readable
  状态以及 `service=gemini`、`account=antigravity` 的 item 元数据。
- strict six-field provider session 进入 `import-known` 时 fail-closed：state 与 active-home 不变，
  不 spawn `agy`，提示当前 session 可能由 system credential store 管理并建议直接运行 `agy`。
- 旧 Google `authorized_user`、用户显式 raw token、API key 与 Vertex 行为保持不变。
- 空账号池、macOS、非交互 print prompt 可以走 local-only native passthrough；它不导入、不切换、
  不写 state/active-home，也不进入 repo sync。Keychain unavailable/missing/locked/timeout 会在 spawn
  前退出。
- preflight 与 spawn 无法原子化；native child 额外设置 `BROWSER=/usr/bin/false`，并在双流中检测
  provider 授权证据。命中后 kill/reap 整个 process group、抑制授权 URL 且不重试。这是竞态遏制，
  在 provider 没有 no-browser-login 契约时不声称浏览器绝不会短暂出现。

## 最终 smoke 的隔离方式

最终 release smoke 保留真实 HOME 和 Gemini runtime 路径，使 provider marker 与 `agy` 当前
Keychain 会话保持一致；只用 `--state-dir` 指向一次性空目录。运行前后在不输出摘要值的前提下
比较真实 `oauth_creds.json` 与 companion token 的 digest、mtime 和 size，并比较 `agy` PID 集合：

```text
target/release/sagy say hi returned greeting  PASS
process exit code                             0
real credential digests/mtime/size            unchanged
temporary state directory                     unchanged and empty
new lingering agy process                     none
```

该 smoke 只证明当前本机 provider session 的 local-only launch 可用，不证明 OAuth 多账号切换；
`import-known` 仍按 fail-closed 规则拒绝这个 session。

## 最终本地验收

所有 Cargo 命令均预先设置 `ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary` 与
`GEMINI_HOME=/tmp/sagy-canary`：

```text
cargo fmt --all -- --check                              PASS
cargo check --all-targets --locked                      PASS
cargo clippy --all-targets --locked -- -D warnings      PASS
cargo test --all-targets --locked                       24 个 executable / 504 项 / 0 失败
native_session unit tests                               8/8 PASS
p1_provider_managed_session                             3/3 PASS
p1_bare_prompt                                          5/5 PASS
backlog/verify/t*.sh                                     7 个脚本 / 72 项断言 / 全部 PASS
```

本轮只创建本地提交，不执行 push、tag 或 release。发布前仍需 exact commit 的 Linux quality 与
原生 Windows runner 证据。
