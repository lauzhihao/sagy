# bugs-014 清理死代码、旧别名安装残留与陈旧的 project map

> 本文件是给执行者看的工单。四组改动互相独立，可以按顺序逐个做完再自检。

## 目标

1. 删除仓库中确认无任何调用点的 public API。
2. 安装脚本在升级时清掉旧版本留下的 `flash` / `pro` / `think` 二进制。
3. `.project_map` 重新生成，不再列出已删除的 bin target。
4. 会话续接（`--continue` 注入）的现有行为**不得改变**。

## 改动

### 1. 删除死代码

下列 9 个函数在整个 `src/` 下都没有调用点（已逐个 grep 确认），全部删除。
删除函数本体即可，不要保留空壳或改成私有。

| 文件 | 函数 |
| :--- | :--- |
| `src/adapters/antigravity/mod.rs` | `read_live_identity` |
| `src/adapters/antigravity/usage.rs` | `mark_needs_relogin` |
| `src/core/state.rs` | `UsageSnapshot::is_in_cooldown` |
| `src/core/state.rs` | `AccountRecord::is_api_key` |
| `src/core/state.rs` | `AccountRecord::is_vertex` |
| `src/core/storage.rs` | `bin_dir` |
| `src/core/storage.rs` | `runtime_dir` |
| `src/core/ui.rs` | `Messages::cli_about` |
| `src/core/ui.rs` | `Messages::no_usable_account` |

注意 `no_usable_account` 与 `no_usable_account_hint` 是两个不同的函数，
**只删前者**，后者在 `src/cli/mod.rs` 中有 3 处调用，必须保留。

删除 `mark_needs_relogin` 后，`src/adapters/antigravity/usage.rs` 的
`test_mark_rate_limited_and_relogin` 里会有 3 行引用它而编译失败：

```rust
adapter.mark_needs_relogin(&mut state, acc_id, "Auth error 401");
let usage_relogin = state.usage_cache.get(acc_id).unwrap();
assert_eq!(usage_relogin.status, "AuthError");
assert!(usage_relogin.needs_relogin);
```

把这几行删掉，并把测试名改为 `test_mark_rate_limited`。
**这是本工单唯一允许改动测试的地方**：删除已随生产代码消失的断言。
不要新增任何测试、不要改动其余断言。

如果删除后 `LiveIdentity` 等类型的 import 变成未使用，clippy 会报出来，按提示清理。

### 2. `install.sh` 清理旧别名

在 `install_original_wrapper` 函数之后新增：

```bash
remove_legacy_aliases() {
  local legacy
  for legacy in flash pro think; do
    if [[ -f "${INSTALL_BIN}/${legacy}" ]]; then
      rm -f "${INSTALL_BIN}/${legacy}"
      echo "Removed legacy model alias ${INSTALL_BIN}/${legacy}"
    fi
  done
}
```

并在文件末尾的调用序列里，把它加在 `install_original_wrapper` 之后、
`post_install_import` 之前：

```bash
install_original_wrapper
remove_legacy_aliases
post_install_import
```

### 3. `install.ps1` 清理旧别名

在三条 `Copy-Item` 原来的位置（`$targetExe` 拷贝之后）加入：

```powershell
# 清理旧版本安装的模型别名二进制
foreach ($legacy in @("flash.exe", "pro.exe", "think.exe")) {
    $legacyPath = Join-Path $InstallBin $legacy
    if (Test-Path $legacyPath) {
        Remove-Item $legacyPath -Force
        Write-Host "Removed legacy model alias $legacyPath"
    }
}
```

### 4. 重新生成 `.project_map`

```bash
python3 scripts/map_project.py
```

生成后确认文件里不再出现 `flash.rs` / `pro.rs` / `think.rs` / `bin: flash`。
如果脚本报错或输出路径不对，不要手工编造内容，停下来报告。

## 禁止

- 不要修改 `backlog/verify/` 下的任何文件。
- 除第 1 节明确点名的那几行外，不得新增或修改任何 `#[cfg(test)]` 测试。
- 不要改动 `--continue` 的注入条件或 `has_prompt_or_continue_args` 的实现。
  自检里有 4 条行为断言在锁这个行为，改了就会红。
- 不要改动 `run_passthrough` 的 `resume` 参数。当前的冗余是有意保留的。

## 自检

```bash
bash backlog/verify/bugs-014.sh
```

## 完成信号

```bash
bash backlog/verify/bugs-014.sh
cargo fmt --check
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo clippy --all-targets -- -D warnings
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo test
```

另外跑一次全套回归，确认没有碰坏别的东西：

```bash
for s in 001 002 004 005 006 007 008 011 012 013 014; do
  printf '%-10s ' "bugs-$s"; bash backlog/verify/bugs-$s.sh >/dev/null 2>&1 && echo PASS || echo FAIL
done
```

11 条必须全 PASS。

## 卡住时

连续 3 轮 FAIL 就停下，把最后一次完整输出和 diff 报告出来。
