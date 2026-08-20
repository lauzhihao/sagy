# sagy

[English](./README.md) | [简体中文](./README.zh-CN.md)

`sagy` is a high-performance, cross-platform CLI launcher and smart account manager for Google Antigravity CLI (`agy`), built in Rust. It provides automated multi-account rotation, rate-limit cooldown management, model shortcuts (`flash`, `pro`, `think`), and encrypted account pool synchronization via Git.

This repository contains only open-source code and never contains private accounts, tokens, or credential pools.

---

## 1. Installation

### Unix (macOS / Linux):

```bash
curl -fsSL https://raw.githubusercontent.com/lauzhihao/sagy/main/install.sh | bash
```

### Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/lauzhihao/sagy/main/install.ps1 | iex
```

### Pre-built Binary Targets:

- macOS: `aarch64-apple-darwin` (Apple Silicon), `x86_64-apple-darwin` (Intel)
- Linux: `x86_64-unknown-linux-musl`
- Windows: `x86_64-pc-windows-msvc`

### Build From Source:

```bash
cargo build --release
```

---

## 2. Model Shortcuts & Binaries

`sagy` installs convenient entrypoints in `$SAGY_HOME/bin`:

| Binary | Target Model & Mode |
| :--- | :--- |
| **`sagy`** | Default launcher, auto-selects healthiest account and starts `agy` |
| **`flash`** | Launches with `gemini-3.7-flash-low` for rapid turnaround |
| **`pro`** | Launches with `gemini-3.1-pro-high` for complex reasoning |
| **`think`** | Launches with `gemini-3.7-flash-high` deep thinking mode |
| **`sagy-original`** | Passthrough helper straight to official underlying `agy` |

---

## 3. Command Reference

| Command | Action |
| :--- | :--- |
| `sagy` / `sagy launch` | Refresh usage, switch to best account, and launch Antigravity CLI |
| `sagy auto` | Select and switch to the best account without launching |
| `sagy list` | Print table of all accounts, plan types, health status, and cooldowns |
| `sagy refresh` | Immediately refresh all account health states |
| `sagy use <email/id>` | Manually switch to a specified account |
| `sagy rm <email/id>` | Remove a registered account (supports `-y` to skip confirmation) |
| `sagy add` | Interactively add a new account credential |
| `sagy login` | Add credentials (supports `--token` or `--api-key`) |
| `sagy import-known` | Auto-discover and import existing `~/.gemini` credentials |
| `sagy import-auth <path>` | Import credentials from a JSON or token file |
| `sagy push <repo>` | Encrypt (XChaCha20Poly1305) and push account pool to a Git repository |
| `sagy pull <repo>` | Pull and decrypt account pool from a Git repository |
| `sagy update` | Check and self-update from GitHub Releases |

---

## 4. Encrypted Account Pool Synchronization

Synchronize account pools securely across multiple machines:

1. Set the encryption key (must be identical on all machines):
   ```bash
   export SAGY_POOL_KEY="your-strong-secret-key"
   ```
2. Push local account pool:
   ```bash
   sagy push git@github.com:your-username/my-sagy-pool.git
   ```
3. Pull and decrypt on another machine:
   ```bash
   sagy pull git@github.com:your-username/my-sagy-pool.git
   ```

---

## 5. License

MIT License
