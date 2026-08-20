# bugs-006 每次启动串行阻塞网络探测，无 TTL 缓存

- 严重度: P1 (体验)
- 状态: 待修复
- 引入版本: 2c5e976

## 现象

`ensure_best_account` -> `refresh_all_accounts`（`src/adapters/antigravity/usage.rs:49-54`）
对每个账号**串行**发一次 HTTP 请求，单次超时 5 秒
（`PROBE_TIMEOUT_SECS`，`usage.rs:11`）。

这条路径挂在每一次 `sagy` / `flash` / `pro` / `think` 启动前。
N 个账号最坏情况给启动增加 N x 5 秒。实测 2 个账号走代理约 1.25 秒。

`UsageSnapshot.last_synced_at` 已经在写，但从未被读来判断"是否需要重探"。

## 修复方案

1. 加探测 TTL：`refresh_account_usage` 开头判断
   `now - last_synced_at < PROBE_TTL`（建议 300 秒）时直接返回缓存，
   跳过网络调用。
2. `sagy refresh` 增加强制刷新语义（绕过 TTL），这本来就是该命令的存在意义。
3. 多账号并发探测：用线程池或 `std::thread::scope` 并发，
   把最坏耗时从 N x timeout 压到 timeout。
   注意 `refresh_all_accounts` 目前 `state.accounts.clone()` 后串行写回
   `state.usage_cache`，并发化需要先收集结果再统一合并。
4. 把探测超时从 5 秒降到 2-3 秒；启动路径上的健康检查不值得等 5 秒。

## 验收标准

- [ ] 连续两次 `sagy --dry-run`，第二次不产生任何网络请求（抓包或日志确认）
- [ ] `sagy refresh` 仍然强制重探
- [ ] 5 个账号时 `sagy list` 冷启动耗时不超过单次超时 + 少量开销
- [ ] 网络完全不可达时，启动路径不被阻塞超过一个超时周期
