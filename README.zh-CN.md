# sagy

[English](./README.md) | [简体中文](./README.zh-CN.md)

`sagy` 是一个基于 Rust 开发的 Google Antigravity CLI (`agy`) 智能多账号管理与环境包装启动器。它支持多账号自动优选轮换、429 限流冷却降级、模型快捷入口（`flash`、`pro`、`think`）以及基于 Git 的多机加密账号池同步。

这个仓库只包含纯开源代码，不包含任何个人账号数据、凭据或私有环境文件。

---

## 一、安装

### Unix (macOS / Linux):

```bash
curl -fsSL https://raw.githubusercontent.com/lauzhihao/sagy/main/install.sh | bash
```

### Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/lauzhihao/sagy/main/install.ps1 | iex
```

### 预编译支持平台：

- macOS：`aarch64-apple-darwin` (Apple Silicon), `x86_64-apple-darwin` (Intel)
- Linux：`x86_64-unknown-linux-musl`
- Windows：`x86_64-pc-windows-msvc`

### 从源码编译：

```bash
cargo build --release
```

---

## 二、入口命令与模型快捷方式

安装后，`sagy` 会在 `$SAGY_HOME/bin` 中提供以下便捷入口：

| 命令 | 对应模型与行为 |
| :--- | :--- |
| **`sagy`** | 默认主命令，智能优选最佳账号后启动 `agy` |
| **`flash`** | 快捷绑定 `gemini-3.7-flash` (effort: `low`) 极速启动 |
| **`pro`** | 快捷绑定 `gemini-3.7-pro` (effort: `high`) 旗舰推理启动 |
| **`think`** | 快捷绑定 `gemini-3.7-flash` (effort: `high`) 深度思考模式 |
| **`sagy-original`** | 到底层官方 `agy` 二进制的透明直通辅助命令 |

---

## 三、命令总览

| 命令 | 说明 |
| :--- | :--- |
| `sagy` / `sagy launch` | 刷新状态，优选当前最健康账号，切换环境后启动或恢复 Antigravity CLI |
| `sagy auto` | 优选并切换至最佳账号，但不启动 CLI |
| `sagy list` | 查看所有账号列表、计划类型、健康状态及冷却倒计时 |
| `sagy refresh` | 立即刷新所有账号的状态 |
| `sagy use <email/id>` | 按邮箱或 ID 手动切换到指定账号 |
| `sagy rm <email/id>` | 删除指定的账号凭据（支持 `-y` 跳过确认） |
| `sagy add` | 交互式添加新账号凭据 |
| `sagy login` | 登录/绑定账号（支持 `--token` 或 `--api-key`） |
| `sagy import-known` | 自动扫描本地已有的 `~/.gemini` 凭据并导入 |
| `sagy import-auth <path>` | 从指定的 JSON 凭据或 Token 文件导入账号 |
| `sagy push <repo>` | 使用 `SAGY_POOL_KEY` 强加密 (XChaCha20Poly1305) 推送账号池至 Git 仓库 |
| `sagy pull <repo>` | 从 Git 仓库拉取并解密同步账号池到本地 |
| `sagy update` | 从 GitHub Releases 检查并自动升级二进制 |

---

## 四、加密账号池跨机同步

在多台机器（例如 Mac 工作站与远程 Linux 服务器）之间同步账号池：

1. 设置加密密钥（两端保持一致）：
   ```bash
   export SAGY_POOL_KEY="your-strong-secret-key"
   ```
2. 推送本地账号池：
   ```bash
   sagy push git@github.com:your-username/my-sagy-pool.git
   ```
3. 在另一台机器下拉取并解密导入：
   ```bash
   sagy pull git@github.com:your-username/my-sagy-pool.git
   ```

---

## 五、运行目录结构

默认状态目录位于 `~/.sagy`（可通过 `SAGY_HOME` 环境变量自定义）：

```text
~/.sagy/
  bin/              # 二进制文件 (sagy, flash, pro, think, sagy-original)
  accounts/         # 各独立受管账号凭据与配置
  tmp/              # 临时解压与同步工作区
  state.json        # 本地状态清单与健康缓存
  repo-sync.json    # 上次同步仓库记录
```

---

## 六、开源协议

本项目基于 MIT 许可证开源。
