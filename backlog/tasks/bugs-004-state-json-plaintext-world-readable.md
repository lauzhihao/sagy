# bugs-004 state.json 明文凭据仍为 0644，多处写入漏掉 write_secret_file

- 严重度: P1 (安全)
- 状态: 待修复 (上轮半修)
- 影响面: 所有账号的 oauth_token / refresh_token / api_key

## 现象

上一轮加了 `storage::write_secret_file`（0600），但最关键的 `state.json`
没有用它。实测：

```text
-rw-r--r--  .../.sagy/state.json                                  <- 明文全量凭据
-rw-------  .../.sagy/accounts/<id>/antigravity-oauth-token       <- 已修
```

`state.json` 里逐字段存着 `oauth_token`、`refresh_token`、`api_key` 明文，
是权限最松、内容最全的那一个文件。

## 根因与漏网清单

`src/core/storage.rs:139-143` 的 `save_state` 调用的是 `write_file_atomically`
而非 `write_secret_file`。

其余仍用裸 `fs::write` 写凭据的位置：

| 位置 | 内容 |
| :--- | :--- |
| `src/core/storage.rs:139` (`save_state`) | state.json 全量明文凭据 |
| `src/adapters/antigravity/auth.rs:137` | API key credentials.json |
| `src/adapters/antigravity/repo_sync.rs:202` | pull 下来的 token 文件 |
| `src/adapters/antigravity/repo_sync.rs:211` | pull 下来的 api_key credentials.json |
| `src/adapters/antigravity/repo_sync.rs:224` | pull 下来的 refresh_token credentials.json |

## 修复方案

1. 上述 5 处统一改用 `storage::write_secret_file`。
2. `~/.sagy` 与 `~/.sagy/accounts/<id>` 目录创建时设 0700
   （目前 `fs::create_dir_all` 走默认 umask，通常是 0755）。
3. 增加一次性迁移：`load_state` 时若发现 `state.json` 权限宽于 0600，
   静默收紧并继续（不报错，避免打断正常使用）。
4. 考虑把 `oauth_token` / `refresh_token` / `api_key` 从 `state.json` 移出，
   只留在 `accounts/<id>/` 下的凭据文件里，`state.json` 仅存索引与元数据。
   这是更彻底的方案，但会改变 state 文件格式，需要版本迁移，可作为独立任务。

## 验收标准

- [ ] 全新安装后 `find ~/.sagy -type f -perm +077` 输出为空
- [ ] 已有 0644 的 state.json 在下次运行后被自动收紧到 0600
- [ ] Windows 分支不因 `#[cfg(unix)]` 缺失而编译失败
