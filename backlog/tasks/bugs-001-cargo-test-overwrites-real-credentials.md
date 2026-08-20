# bugs-001 cargo test 覆盖真实 Antigravity 凭据

- 严重度: P0 (已造成实际损害)
- 状态: 待修复
- 引入版本: 2c5e976 / 586e9a9 (fix 轮次新增的测试)
- 影响面: 任何执行 `cargo test` 的开发机与 CI runner

## 现象

执行 `cargo test` 会把 `~/.gemini/antigravity-cli/antigravity-oauth-token` 的内容
覆盖为测试常量 `jwt_token_sample`，导致本机 agy 登录态被破坏。

已在操作者本机确认发生（2026-08-20 10:10:12）:

```text
实际文件 sha256          = 084a08a15929ed58...
'jwt_token_sample' sha256 = 084a08a15929ed58...
```

## 根因

`src/adapters/antigravity/auth.rs:204-223` 的 `test_switch_token_account_writes_token_file`
直接调用 `switch_account()`。`switch_account` 内部通过
`paths::default_antigravity_cli_home()` 解析写入目标，该函数在未设置
`ANTIGRAVITY_CONFIG_DIR` 时回退到真实 `$HOME/.gemini/antigravity-cli`，
测试没有做任何隔离。

`src/adapters/antigravity/auth.rs:184-202` 的
`test_switch_api_key_account_does_not_mutate_oauth_files` 同属一类风险，
只是当前 ApiKey 分支不写文件才侥幸无害。

## 复现

```bash
ANTIGRAVITY_CONFIG_DIR=/tmp/probe GEMINI_HOME=/tmp/probe-gemini cargo test
ls -l /tmp/probe/antigravity-oauth-token   # 16 字节, 内容为 jwt_token_sample
```

不带这两个环境变量时，同一个文件会落到真实 `~/.gemini/antigravity-cli/` 下。

## 修复方案

二选一，推荐 A：

A. 删除这两个测试。它们只断言 `is_ok()`，不校验任何写入结果，验证价值为零，
   却带有破坏宿主机状态的副作用。属于"阻塞有效验证的有害测试"。

B. 若保留，必须在测试内隔离目标目录：用 `tempfile::tempdir()` 生成目录后
   设置 `ANTIGRAVITY_CONFIG_DIR` / `GEMINI_HOME` 指向它，并确保测试串行执行
   （环境变量是进程全局的，`cargo test` 默认多线程，需要 `--test-threads=1`
   或改用参数注入而非全局 env）。

更彻底的结构性修法：给 `switch_account` 增加显式的目标目录参数，
由调用方传入，从函数签名上消除"隐式读真实 HOME"的能力。

## 验收标准

- [ ] 在未设置 `ANTIGRAVITY_CONFIG_DIR` / `GEMINI_HOME` 的干净环境执行 `cargo test`，
      `~/.gemini/` 下无任何文件被创建或修改（用 `find ~/.gemini -newermt` 校验）
- [ ] `cargo test` 全绿
- [ ] `cargo clippy --all-targets -- -D warnings` 全绿

## 附带待办

操作者本机凭据需要恢复：`~/.gemini/oauth_creds.json` 中的 `refresh_token` 完好，
执行一次 agy 让其自行续期即可重建 token 文件。此项独立于代码修复。
