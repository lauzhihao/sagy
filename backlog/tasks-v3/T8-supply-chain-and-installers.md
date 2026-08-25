# T8 安装器、自更新与 CI（P2/P3）

先读 `backlog/tasks-v3/COMMON.md`。
背景见审计报告的 INSTALL-002、CI-001，以及 P3 的下载无 size 上限、Action 未固定 SHA、
`is_newer_version` 死代码、`sagy-original` 解析顺序不一致。

## 归属文件（只能改这些）

- `src/core/update.rs`
- `install.sh`
- `install.ps1`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `tests/p0_checksum.rs`
- `tests/ci_workflow.rs`

## AC-1（P2）install.ps1 的解压目录必须是一次性的

现状：解压到固定的 `$SagyHome\tmp`，成功路径只删 zip，不删解压出来的 `sagy.exe` 和
`SHA256SUMS.txt`。下一次若归档结构变化或解压部分失败，残留的旧 `sagy.exe` 会满足完整性守卫，
把上一个版本当作新版本装上（fail-open）。

- AC-1.1 每次安装使用独立的一次性临时目录，成功与失败路径都必须清理干净。
- AC-1.2 归档里缺少顶层二进制时必须 fail-closed：非 0 退出、不安装、不覆盖已有二进制。
- AC-1.3 两个 installer 并发执行不得互相覆盖对方的临时文件。
- AC-1.4 `install.sh` 的等价行为必须保持（它已经用 `mktemp -d` + `trap` 清理，不要退化）。

## AC-2（P2）Windows 侧的 checksum fail-closed 必须被真正执行

现状：`tests/p0_checksum.ps1` 从未被任何 workflow 引用，`install.ps1` 的 fail-closed
只有 Rust 侧的字符串断言（`source.contains(...)`），任何一次重构都可能静默回归成 fail-open。

- AC-2.1 `tests/p0_checksum.ps1` 必须被 CI 的 Windows job 真正执行。
- AC-2.2 该脚本必须覆盖：checksum 404、超时、空文件、条目缺失、hash 不匹配、无 hash 工具，
  每一条都断言"非 0 退出且目标二进制未被替换"。
- AC-2.3 `tests/p0_checksum.rs` 里纯字符串比对的断言必须被真正执行行为的断言取代或补强；
  不得只靠 `source.contains(...)` 作为唯一证据。

## AC-3（P3）安装失败不得被吞掉

- AC-3.1 `install.sh` 的安装后动作不得用 `>/dev/null 2>&1` 吞掉失败后继续打印安装成功。
  失败必须对用户可见（至少打印一条 ASCII 提示说明哪一步失败了）。
- AC-3.2 `install.ps1` 的等价路径同样处理。
- AC-3.3 安装脚本自身的退出码必须如实反映安装是否成功。

## AC-4（P3）下载必须有体积上限

- AC-4.1 `sagy update` 的 release metadata 与二进制下载都必须有明确的字节上限，
  超限即 fail-closed。
- AC-4.2 两个安装脚本的对应下载同样有上限。
- AC-4.3 上限值必须是常量并有注释说明依据。

## AC-5（P3）第三方 Action 固定到 commit SHA

- AC-5.1 `release.yml` 与 `ci.yml` 里所有第三方 Action 按 40 位 commit SHA 固定，
  并在同一行注释保留原来的版本 tag 便于人读。
- AC-5.2 持有 `contents:write` 的 job 的权限范围必须最小化，在报告里说明你保留了哪些、为什么。

## AC-6（P3）删除语义更弱的版本比较入口

- AC-6.1 `update.rs` 中已无生产调用方的版本比较 `pub` 函数必须删除（非法版本静默返回 false
  的那个），保留严格 semver 的那条路径。
- AC-6.2 删除后既有的更新决策测试必须继续通过。

## AC-7（P3）两个 installer 的 `sagy-original` 解析顺序必须一致

- AC-7.1 同一台机器上同时存在 PATH 上的 agy 和 `~/.gemini` 下的 agy 时，
  两个平台必须选择同一个来源。
- AC-7.2 选定的顺序必须在脚本内有注释说明。

## 自检

除通用门禁外，AC-1.2 与 AC-3.1 必须给出脚本级复现（可以用 fake 下载源在本地跑）。
