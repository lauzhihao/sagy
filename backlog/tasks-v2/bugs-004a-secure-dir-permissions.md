# bugs-004a ~/.sagy 下的目录权限收紧到 0700

> 本文件是给执行者看的工单。只改一个文件里的一个函数。

## 目标

`~/.sagy` 及其下所有子目录（含 `accounts/` 和 `accounts/<id>/`）的权限必须是 0700，
不允许 group/other 访问。目前 `accounts/` 是 0755。

## 背景（不需要照做，只是解释为什么）

`create_secure_dir_all` 已经存在且会把**叶子目录**设成 0700，
但它内部调用的 `fs::create_dir_all` 一次性创建整条路径，中间层目录仍是 umask 默认的 0755。
另外 `write_secret_file` 走的是 `write_file_atomically`，后者用的是裸 `fs::create_dir_all`。

## 改动

1. `src/core/storage.rs` 的 `fn create_secure_dir_all`（约第 71 行）
   把整个函数体改成逐级创建并逐级设权限：

   ```rust
   pub fn create_secure_dir_all(path: &Path) -> Result<()> {
       let mut current = PathBuf::new();
       for component in path.components() {
           current.push(component);
           if current.as_os_str().is_empty() || current.exists() {
               continue;
           }
           fs::create_dir(&current)
               .with_context(|| format!("failed to create directory {}", current.display()))?;
           #[cfg(unix)]
           {
               use std::os::unix::fs::PermissionsExt;
               if let Ok(metadata) = fs::metadata(&current) {
                   let mut perms = metadata.permissions();
                   perms.set_mode(0o700);
                   let _ = fs::set_permissions(&current, perms);
               }
           }
       }
       Ok(())
   }
   ```

2. `src/core/storage.rs` 的 `fn write_file_atomically`
   把创建父目录那一句
   ```rust
   fs::create_dir_all(parent)
       .with_context(|| format!("failed to create directory {}", parent.display()))?;
   ```
   改成
   ```rust
   create_secure_dir_all(parent)?;
   ```

3. `src/adapters/antigravity/account.rs` 与 `src/adapters/antigravity/repo_sync.rs` 中
   所有用于创建账号目录的 `fs::create_dir_all(&acc_dir)` 全部改为
   `storage::create_secure_dir_all(&acc_dir)`。
   （用 `grep -rn "create_dir_all" src/` 找全，除 `src/core/storage.rs` 内部实现和
   `#[cfg(test)]` 里的以外，全部替换。）

## 禁止

- 不要修改 `backlog/verify/` 下的任何文件。
- 不要新增或修改单元测试。
- 不要改动 `~/.gemini` 相关的写入逻辑（那是另一个工单的范围）。

## 自检

```bash
bash backlog/verify/bugs-004.sh
```

## 完成信号

```bash
bash backlog/verify/bugs-004.sh
cargo fmt --check
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo clippy --all-targets -- -D warnings
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo test
```

## 卡住时

连续 3 轮 FAIL 就停下报告。
