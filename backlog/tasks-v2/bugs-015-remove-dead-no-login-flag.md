# bugs-015 移除只接收不生效的 `--no-login` 参数

> 本文件是给执行者看的工单。纯删除，不新增任何行为。

## 目标

`--no-login` 目前会被 CLI 接收、写进帮助文本，但实际不产生任何效果
（`ensure_best_account` 的形参写成 `_no_login`，从头到尾没被使用）。
sagy 也不存在"登录引导"这个流程，所以这个参数没有可实现的语义。整体删除。

## 改动

### 1. `src/cli/args.rs`

删除 `LaunchArgs` 与 `AutoArgs` 两个结构体中的 `no_login` 字段及其
`#[arg(...)]` 属性（共两处）。

### 2. `src/cli/mod.rs`

- 删除默认构造 `LaunchArgs { ... }` 里的 `no_login: false,` 那一行。
- 删除两处 `ensure_launch_account(...)` 调用中传入的 `args.no_login,` 实参。

### 3. `src/cli/launch.rs`

删除 `ensure_launch_account` 的 `no_login: bool` 形参，
以及它转发给 `adapter.ensure_best_account(...)` 时的对应实参。

### 4. `src/adapters/antigravity/mod.rs`

删除 `ensure_best_account` 的 `_no_login: bool` 形参。

### 5. `src/cli/help.rs`

在四段帮助文本（launch 中英文、auto 中英文）里删掉 `--no-login` 那一行。
注意保留同一段落里其它选项的对齐与换行格式。

## 禁止

- 不要修改 `backlog/verify/` 下的任何文件。
- 不要新增或修改 `#[cfg(test)]` 测试。
- 不要动 `--dry-run` / `--no-resume` / `--no-launch` / `--no-import-known`
  这四个参数的任何行为，自检里有 5 条断言在锁它们。
- 不要顺手"实现" `--no-login`。删除是本工单的既定结论。

## 自检

```bash
bash backlog/verify/bugs-015.sh
```

## 完成信号

```bash
bash backlog/verify/bugs-015.sh
cargo fmt --check
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo clippy --all-targets -- -D warnings
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo test
```

全套回归，12 条必须全 PASS：

```bash
for s in 001 002 004 005 006 007 008 011 012 013 014 015; do
  printf '%-10s ' "bugs-$s"; bash backlog/verify/bugs-$s.sh >/dev/null 2>&1 && echo PASS || echo FAIL
done
```

## 卡住时

连续 3 轮 FAIL 就停下报告。
