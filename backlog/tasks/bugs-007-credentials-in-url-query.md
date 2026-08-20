# bugs-007 探测把 API key / access token 放进 URL query string

- 严重度: P1 (安全)
- 状态: 待修复
- 引入版本: 2c5e976

## 现象

`src/adapters/antigravity/usage.rs:93-96`:

```text
https://generativelanguage.googleapis.com/v1beta/models?key=<API_KEY>
```

`src/adapters/antigravity/usage.rs:137-140`:

```text
https://oauth2.googleapis.com/tokeninfo?access_token=<ACCESS_TOKEN>
```

凭据出现在 URL 中意味着它会被写入：服务端访问日志、任何中间 HTTP 代理的日志、
本机代理软件的日志。操作者当前环境就设置了 `HTTP_PROXY` / `HTTPS_PROXY`，
这条路径是实际存在的。

## 修复方案

1. API key 探测改用 header：`x-goog-api-key: <key>`，URL 去掉 `?key=`。
2. access token 探测改用 `Authorization: Bearer <token>`。
   注意 `oauth2.googleapis.com/tokeninfo` 是旧接口，建议改用
   `https://www.googleapis.com/oauth2/v3/tokeninfo` 或直接改成
   带 Bearer 的轻量业务接口探测。
3. 顺带检查错误信息与日志输出，确保 `last_sync_error` 不会把完整 URL
   （含凭据）写进 `state.json`。当前 `usage.rs:127` / `usage.rs:158` 的
   `format!("...{e}")` 会把 reqwest 的错误字符串带上 URL，
   实测已确认 `state.json` 里出现了完整的 `?access_token=...`。

## 证据

沙箱中 `state.json` 实际落盘内容：

```text
"last_sync_error": "Token probe error: error sending request for url
 (https://oauth2.googleapis.com/tokeninfo?access_token=ya29.EXPIRED_...)"
```

即凭据不仅进了 URL，还被持久化进了一个 0644 的文件（见 bugs-004）。

## 验收标准

- [ ] 两个探测请求的 URL 中不含任何凭据
- [ ] `state.json` 的 `last_sync_error` 中不含凭据片段
- [ ] 探测功能行为不变（成功/429/401 三条分支各验证一次）
