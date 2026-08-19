# Architecture

`sagy` (Super Antigravity) is a cross-platform, account-aware launcher and orchestrator for Google Antigravity CLI (`agy`).

## 1. System Overview

```text
               +----------------------------------+
               |  CLI Entrypoints (sagy / flash)  |
               +-----------------+----------------+
                                 |
                                 v
               +----------------------------------+
               |            CLI Router            |
               | (args.rs, launch.rs, help.rs)    |
               +-----------------+----------------+
                                 |
                 +---------------+---------------+
                 |                               |
                 v                               v
+--------------------------------+ +-----------------------------+
|          Core Engine           | |     Antigravity Adapter     |
| - Storage (atomic persistence) | | - Binary Discovery (agy)    |
| - Policy (scoring & cooldown)  | | - Account Model (OAuth/API) |
| - UI (ANSI tables & messages)  | | - Env & Profile Switcher    |
| - Update (GitHub release DL)   | | - AES-256-GCM Repo Sync     |
+--------------------------------+ +-----------------------------+
                 |                               |
                 +---------------+---------------+
                                 |
                                 v
               +----------------------------------+
               |     Subprocess Execution         |
               |     (Official agy CLI)           |
               +----------------------------------+
```

## 2. Directory Layout & State Resolution

- **Default Home**: `~/.sagy` (can be overridden via `SAGY_HOME` or `--state-dir <path>`).
- **Layout**:
  ```text
  ~/.sagy/
    bin/              # Installed executable binaries (sagy, flash, pro, think, sagy-original)
    runtime/          # Optional local toolchains or runtimes
    tmp/              # Temporary download, extraction and repo-sync working trees
    accounts/         # Isolated account directories (<account-id>/credentials.json, token)
    state.json        # Atomic state file (account inventory, current account, usage cache)
    repo-sync.json    # Last synced repository configuration
  ```

## 3. Account Selection & Cooldown Policy

1. **Stickiness**: If the currently active account is healthy (not in cooldown, no re-login flag, positive quota remaining), `sagy` keeps using it to prevent churn.
2. **Account Scoring**:
   - Accounts requiring re-login receive a `-10000.0` penalty.
   - Accounts in active rate-limit cooldown (`429 ResourceExhausted`) receive a `-5000.0` penalty + remaining cooldown duration penalty.
   - Positive score bonuses for remaining quota percentage, Pro/Advanced plans, and recent usage history.
3. **Automatic Fallback**: When an active account is rate-limited, it enters a 5-minute cooldown window, and subsequent `sagy launch` calls smoothly fall back to the next healthiest available account.

## 4. Encrypted Account Pool Synchronization

- **Algorithm**: `XChaCha20Poly1305` authenticated encryption with SHA-256 key derivation.
- **Key Source**: `SAGY_POOL_KEY` environment variable.
- **Payload Format**: Encrypted bundle (`.sagy-account-pool/bundle.enc.json`) committed to a private Git repository.
- **Cross-Host Workflow**:
  - `sagy push <repo>`: Exports local accounts, encrypts into bundle, commits and pushes to Git.
  - `sagy pull <repo>`: Clones repository, decrypts bundle, merges accounts into local state, and refreshes usage cache.
