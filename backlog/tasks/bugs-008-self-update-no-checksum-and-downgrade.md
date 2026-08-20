# bugs-008 自更新无完整性校验，且版本比较可导致降级

- 严重度: P2 (安全 / 供应链)
- 状态: 待修复

## 现象

1. **无校验**：CI 已经产出 `SHA256SUMS.txt`（`.github/workflows/release.yml`
   publish job），但 `src/core/update.rs` 和 `install.sh` / `install.ps1`
   都不下载、不比对。checksum 目前只是给人肉看的装饰。
   grep 确认三个文件中均无 sha256/checksum 相关代码。
2. **可降级**：`src/core/update.rs:58` 用 `asset.version == previous_version`
   做判断。远端 latest tag 比本地版本更旧时（误发布、tag 回滚），
   会被当作"有新版本"直接替换成旧二进制。
3. **无 HTTP 超时**：`http_client()`（`update.rs:224-233`）没有 `.timeout()`，
   网络劣化时 `sagy update` 会无限期挂起。
   注意 `usage.rs` 的 probe client 已经设了超时，两处不一致。

## 修复方案

1. `download_release_binary` 后、写入临时文件前，计算 SHA-256 并与
   同 release 的 `SHA256SUMS.txt` 条目比对，不匹配则 `bail!`。
   `sha2` 已在依赖里，无需新增 crate。
2. `install.sh` 增加同样的校验（`shasum -a 256 -c` 或手工比对），
   `install.ps1` 用 `Get-FileHash`。
3. 版本比较改为语义化比较：只在远端版本严格大于本地时才更新，
   `--force` 才允许同版本或降级。可手工解析 `major.minor.patch`，
   不必引入 `semver` crate。
4. `http_client()` 加 `.timeout(Duration::from_secs(30))`
   和 `.connect_timeout(...)`。

## 验收标准

- [ ] 篡改一个本地 release 归档后执行更新流程，能因 checksum 不匹配而拒绝
- [ ] 远端 tag 低于本地版本时，不加 `--force` 不会替换二进制
- [ ] 断网或极慢网络下 `sagy update` 在 30 秒内失败退出而非挂死
