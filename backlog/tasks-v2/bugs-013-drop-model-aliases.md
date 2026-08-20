# bugs-013 删除 flash/pro/think 别名入口，sagy 统一使用最新 flash 模型

> 本文件是给执行者看的工单。这是一次设计调整，不是缺陷修复。
> 操作者决定：sagy 不按模型分入口；默认就用最新的 flash 模型；
> 需要 pro 时由用户在 agy 交互界面内自行切换。

## 目标

1. `flash` / `pro` / `think` 三个别名二进制及其全部相关逻辑彻底移除。
2. 无论以哪种形式启动（裸 `sagy`、`sagy <prompt>`、`sagy launch`），
   都注入 `--model gemini-3.7-flash-high`。
3. 用户显式传了 `--model` 时不覆盖用户的选择。

## 改动

### 1. `src/adapters/antigravity/launcher.rs`

把文件顶部的三个模型常量
```rust
const FLASH_MODEL_ID: &str = "...";
const PRO_MODEL_ID: &str = "...";
const THINK_MODEL_ID: &str = "...";
```
替换为一个
```rust
// agy models 的真实标识。effort 烧在 ID 内, 不再单独传 --effort。
const DEFAULT_MODEL_ID: &str = "gemini-3.7-flash-high";
```

把 `launch_agy` 里「3. Inspect binary alias invocation for model shortcuts」
整段（从 `let mut final_args = Vec::new();` 到该 `if let Some(exe_name) = ...` 块结束）
替换为：
```rust
        // 3. 注入默认模型。用户显式指定 --model 时不覆盖。
        let mut final_args = Vec::new();
        if !contains_flag(extra_args, "--model") {
            final_args.push(OsString::from("--model"));
            final_args.push(OsString::from(DEFAULT_MODEL_ID));
        }
```

删除因此变得未使用的 `use std::env;`。

### 2. `src/cli/mod.rs`

在 `parse_args` 中删除这三段：
- `let exe_name = raw_args.first()...unwrap_or_default();`
- `let is_alias = exe_name.contains("flash") || ...;`
- 整个 `if is_alias { ... }` 分支

保留其后的 `if raw_args.len() > 1 && !has_known_subcmd { ... }` 分支不变。

### 3. `src/core/update.rs`

删除第 117 行的调用 `sync_sibling_binaries(&executable_path);`，
并删除整个 `fn sync_sibling_binaries`（约第 128 行起）。别名不存在了，这个函数没有用途。

### 4. `install.sh`

删除第 10-12 行的 `FLASH_PATH` / `PRO_PATH` / `THINK_PATH` 变量定义，
删除第 127-129 行的三条 `cp`，删除第 162 行提到别名的那句 echo。

### 5. `install.ps1`

删除拷贝 `flash.exe` / `pro.exe` / `think.exe` 的三条 `Copy-Item`，
并把结尾的 `Write-Host "Binaries: sagy, flash, pro, think, sagy-original"`
改为 `Write-Host "Binaries: sagy, sagy-original"`。

### 6. `src/cli/help.rs`

中英文两段帮助文本里，删除 `flash` / `pro` / `think` 三行用法说明。

### 7. `README.md` 与 `README.zh-CN.md`

删除「Model Shortcuts / 模型快捷入口」表格中 `flash`、`pro`、`think` 三行，
只保留 `sagy` 与 `sagy-original` 两行。并在 `sagy` 那行说明
默认使用 `gemini-3.7-flash-high`，切换其它模型请在 agy 界面内操作。

### 8. `ARCHITECTURE.md`

目录布局里 `bin/` 的注释改为只列 `sagy` 与 `sagy-original`。

## 禁止

- 不要修改 `backlog/verify/` 下的任何文件。
- 不要新增或修改 `#[cfg(test)]` 单元测试。
- 不要顺手改动本工单未列出的行为（例如 `--continue` 的注入条件，那是另一个议题）。

## 自检

```bash
bash backlog/verify/bugs-013.sh
```

## 完成信号

以下四条全部 PASS：

```bash
bash backlog/verify/bugs-013.sh
cargo fmt --check
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo clippy --all-targets -- -D warnings
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo test
```

clippy 会指出因删除而变得未使用的 import 或函数，按它的提示一并清理。

## 卡住时

连续 3 轮 FAIL 就停下，把最后一次完整输出和 diff 报告出来。
