# bugs-009 sync_sibling_binaries 自拷贝会把二进制清零

- 严重度: P2 (当前不可达的潜伏缺陷)
- 状态: 待修复
- 引入版本: f1fad6f

## 现象

`src/core/update.rs:103-123` 的 `sync_sibling_binaries` 对
`["flash", "pro", "think"]` 逐个执行 `fs::copy(source_exe, target_path)`，
没有判断 `target_path` 是否就是 `source_exe` 本身。

macOS 上 `std::fs::copy(p, p)` 会**把文件截断为 0 字节并返回 Ok**，实测：

```text
before: 4096 bytes
copy ok, 0 bytes
after:  0 bytes
```

若 `source_exe` 恰好名为 `flash`，循环会先把 flash 清零，
再用这个 0 字节文件覆盖 pro 和 think，三个入口一起报废。

## 当前是否可达

不可达。因为 `src/cli/mod.rs:90-96` 的 alias 路由会把 `flash update`
改写成"把 update 当作 prompt 传给 agy"（见 bugs-010），
`update` 子命令在 alias 二进制上根本执行不到。

一旦 bugs-010 调整了 alias 路由，这个缺陷立即变成可达的 P0。
因此必须在动 alias 路由之前先修掉。

## 修复方案

循环内加一行守卫：

```rust
if target_path == source_exe { continue; }
```

更稳妥的做法是比较 canonicalize 后的路径，覆盖符号链接与相对路径的情况。

同时建议：拷贝到临时文件后再 rename 到目标，避免拷贝中途失败留下半截二进制。

## 验收标准

- [ ] 构造 source_exe 与某个 alias 同名的场景，执行同步后该文件大小不变
- [ ] 正常 `sagy update` 场景下 flash/pro/think 三个副本仍被正确同步且可执行
