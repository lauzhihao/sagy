# bugs-012 死代码、重复实现与环境依赖测试清理

- 严重度: P3 (可维护性)
- 状态: 待修复

## 清单

### 1. `mark_needs_relogin` 是死代码

`src/adapters/antigravity/usage.rs:69-78` 定义后只有它自己的测试调用
（`usage.rs:245`）。生产路径上 probe 直接改 `usage.needs_relogin` 字段，
没有走这个方法。要么改为由 probe 统一调用，要么删除。

### 2. 两个逐字节相同的函数

`src/cli/mod.rs:133-165` 的 `rewrite_alias_args` 与
`src/cli/mod.rs:167-199` 的 `rewrite_passthrough_launch_args` 实现完全一致。
合并为一个函数。（与 bugs-010 的修复一并做）

### 3. if 两个分支返回同一个值

`src/adapters/antigravity/mod.rs:106-111`:

```rust
if state.accounts.is_empty() {
    if no_login {
        return Ok(None);
    }
    return Ok(None);
}
```

`no_login` 分支没有任何实际作用。要么实现 no_login 为 false 时的交互式登录引导，
要么删掉这层判断。注意 `--no-login` 这个参数目前对外承诺的语义
（"没有可用账号时不提示登录"）实际并未实现。

### 4. `test_find_git_bin` 依赖宿主机环境

`src/adapters/antigravity/paths.rs:127-131` 断言宿主机装了 git。
在最小化容器或未装 git 的构建环境中会红。
应改为断言"函数不 panic"，或直接删除（该测试验证价值很低）。

### 5. `#![allow(dead_code)]` 覆盖整个 state 模块

`src/core/state.rs:1` 的模块级 allow 会掩盖后续新增的真实死代码。
建议收窄到具体项上。

### 6. 残留的构建产物

`target/release/flash`、`target/release/pro`、`target/release/think`
是 Cargo.toml 移除多 bin target 之前的遗留物，`cargo clean` 一次即可。

## 修复方案

按上述清单逐项处理。第 2、3 项与 bugs-010 有重叠，建议合并到同一次改动。

注意：第 4 项属于测试代码调整，如果由 agent 执行，只能做"删除已失效/有害测试"，
不能新增或改写单元测试断言。

## 验收标准

- [ ] `cargo clippy --all-targets -- -D warnings` 全绿
- [ ] `cargo fmt --check` 全绿
- [ ] 无重复实现的孪生函数
- [ ] `--no-login` 要么被实现，要么从 CLI 与文档中移除
