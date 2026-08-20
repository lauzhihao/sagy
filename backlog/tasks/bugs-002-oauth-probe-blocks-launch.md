# bugs-002 健康探测把可续期的过期 token 判死，导致 sagy 拒绝启动

- 严重度: P0 (必然触发，工具不可用)
- 状态: 待修复
- 引入版本: 2c5e976
- 影响面: 所有 OAuth 账号，即操作者的主要使用路径

## 现象

`sagy` / `sagy list` 会把正常可用的账号标成 `Relogin Required`，
随后 `sagy` 直接拒绝启动：

```text
$ sagy list
*  exp@example.com   oauth  ...  Relogin Required  0%
$ sagy
No usable accounts found. Run `sagy add`, `sagy login`, or `sagy import-known` first.
exit=1
```

## 根因

1. `src/adapters/antigravity/usage.rs:132-179`：对 `ya29.` 开头的 token 请求
   `oauth2.googleapis.com/tokeninfo`，HTTP 400/401 即置 `needs_relogin = true`。
2. `src/core/policy.rs:59-61`：`needs_relogin` 直接给 -10000 分。
3. `src/core/policy.rs:49-52`：新加的 `score > 0.0` 过滤把它整个排除。
4. 全代码库没有任何 refresh 流程：`refresh_token` 只被存储与搬运，
   从未用于换取新的 access token（grep 确认）。

Google access token 有效期约 1 小时，而 agy 自己会用 refresh_token 静默续期。
sagy 把"access token 过期但可续期"这一完全正常的状态判成了终态失效。

## 影响验证

操作者真实 `~/.gemini/oauth_creds.json`:

```text
expiry_date = 1776700300397  -> 2026-04-20 15:51:40 UTC (已过期 4 个月)
refresh_token 存在
```

agy 照常工作，sagy 会拒绝启动。这是当下就会发生的故障，不是理论风险。

同一逻辑也作用于 JWT 分支（`usage.rs:161-177`，`extract_jwt_exp` 判 `exp`），
Antigravity 的 JWT 同样是短期票据，结论一致。

## 修复方案

核心原则：**探测只用于排序降权，不用于判死；判死权交给 agy。**

1. 引入 `Stale` 状态：探测返回 400/401 时，
   - 若 `refresh_token.is_some()` 或该账号来自 `oauth_creds.json`
     -> `status = "Stale"`，`needs_relogin = false`，仅小幅扣分（例如 -200），
       仍允许被选中并启动
   - 若确实没有任何续期材料 -> 才置 `needs_relogin = true`
2. `policy::score_account` 相应增加 `Stale` 的温和扣分档位。
3. 保留 `score > 0.0` 过滤（bugs-P1-3 的修复正确），但确保 `Stale` 落在正分区间。

可选增强（非本任务必须）：实现真正的 refresh flow，用 refresh_token 换新
access token 并回写 `oauth_creds.json`。若实现，需注意这会与 agy 并发写同一文件。

## 验收标准

- [ ] 构造一个持有过期 `ya29.` token 且带 `refresh_token` 的账号，
      `sagy --dry-run` 能选中它，`sagy` 能正常拉起 agy
- [ ] 构造一个无 refresh_token 且 token 无效的账号，仍被正确标记为需重登
- [ ] 全部账号均不可用时，`sagy` 仍输出 no-usable-account 提示并 exit 1（不回退）
- [ ] 沙箱验证（独立 HOME + SAGY_HOME + 假 agy 脚本），不依赖新增单元测试

## 依赖

无。应最先于 bugs-003 修复，因为在本问题修好前无法端到端验证启动链路。
