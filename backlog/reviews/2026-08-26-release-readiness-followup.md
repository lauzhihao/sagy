# sagy 发布就绪跟进（2026-08-26）

## 结论

2026-08-25 审计遗留的 GitHub Actions job context 错误与 authorized-user `token_uri`
兼容问题已在本地关闭，README、架构和 backlog 已与实现同步。本地 Rust 门禁、workflow
静态解析和 7 组离线黑盒验收全绿。

当前仍不能声称“远端 CI 已通过”或“已发布”：本轮没有 push、tag 或 GitHub Release，
因此 exact commit 的原生 Windows runner 证据尚未产生。一键安装器与 `sagy update` 仍需等待
首个 release，当前安装方式是源码编译。

## 本轮关闭项

### 1. GitHub Actions runner context 与凭据沙箱

- 删除 job-level `env` 对 `${{ runner.temp }}` 的提前求值。
- 新增 `.github/actions/setup-sagy-sandbox/action.yml`，在 runner 已分配且 checkout 完成后，
  从运行时 `RUNNER_TEMP` 派生并创建隔离的 `HOME`、`SAGY_HOME`、`GEMINI_HOME`、
  `ANTIGRAVITY_CONFIG_DIR` 与 `CARGO_HOME`。
- Unix 分支使用 `umask 077`；Windows 分支显式创建目录并在失败时停止。
- 所有执行 Cargo 的 CI/release jobs 都在 Rust toolchain setup 与首个 Cargo 命令之前调用该 action；
  publish job 不 checkout、不运行 Cargo，也不取得该沙箱。
- Windows workflow 显式构建真实 `sagy.exe`，运行 `tests/p0_checksum.ps1` 并传播退出码。
- workflow 中的第三方 Actions 均固定到 40 位 commit SHA；只有 publish job 拥有
  `contents: write`。

### 2. Google authorized-user 兼容性

- `client_id`、`client_secret` 与 `refresh_token` 仍为必填字段。
- 缺失 `token_uri` 的 provider-valid 文档在内部规范为精确的
  `https://oauth2.googleapis.com/token`。
- 显式给出任何其它 endpoint 或非字符串值时 fail-closed，错误不回显不可信值。
- 缺失 endpoint 与显式 canonical endpoint 得到相同 fingerprint。
- active-home/import-known 采用时保留原始字节；portable credential 和 repo bundle
  序列化为 canonical form；未知字段保持不丢失。

### 3. 文档与防回退

- README 中不再把尚无 release 的一键安装器写成当前可用路径。
- README 与 `ARCHITECTURE.md` 记录完整的 12 项 child auth env 清理面、`Degraded`
  探测降级策略和 authorized-user canonical endpoint。
- 新增文档一致性测试，防止旧的“三变量清理”说法或未发布安装状态回流。

## 本地验收证据

所有 Cargo 命令均设置：

```text
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
GEMINI_HOME=/tmp/sagy-canary
```

结果：

```text
cargo fmt --all -- --check                              PASS
cargo check --all-targets --locked                      PASS
cargo clippy --all-targets --locked -- -D warnings      PASS
cargo test --all-targets --locked                       22 个 test executable / 485 项 / 0 失败
actionlint .github/workflows/*.yml                       PASS
composite action YAML parse                              PASS
```

离线黑盒验收：

| 脚本 | 结果 |
| :--- | :--- |
| `t1-state-root.sh` | 18/18 PASS |
| `t2-migration.sh` | 6/6 PASS |
| `t4-repo-sync.sh` | 14/14 PASS |
| `t6-offline.sh` | 5/5 PASS |
| `t7-cli.sh` | 11/11 PASS |
| `t10-sync-commit.sh` | 8/8 PASS |
| `t11-first-run.sh` | 10/10 PASS |

合计 72/72 PASS。

## 发布前仍需的外部证据

1. 将当前变更 push 到 GitHub 后，观察 exact commit 的 Linux `quality` 与原生 Windows
   `windows-runtime` jobs；本地 macOS 不能替代 Windows runner 的 filesystem/PowerShell 证据。
2. Windows job 必须同时通过 `cargo test --all-targets --locked`、`windows_runtime` smoke test
   和真实二进制 checksum harness。
3. 本轮不创建 tag、不触发 release workflow、不发布资产。是否发布由后续单独批准。

## 独立后续项

- Vertex service-account 文档自身的 `token_uri` endpoint 信任策略未纳入本轮 authorized-user
  兼容修改，需要单独做 security review；本轮没有扩大该凭据类型的公共接口或行为。
- 2026-08-25 报告列出的 minor 残留仍保留，不被本次发布就绪修复隐式关闭。
