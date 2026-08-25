# Architecture

`sagy` (Super Antigravity) is a cross-platform, account-aware launcher and orchestrator for Google Antigravity CLI (`agy`).

## 1. System Overview

```text
               +-----------------------------------------+
               |  CLI Entrypoints (sagy / sagy-original) |
               +--------------------+--------------------+
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
| - State v2 (CAS transactions)  | | - Binary Discovery (agy)    |
| - Policy (eligibility tiers)   | | - OAuth/API/Vertex Model    |
| - UI (ANSI tables & messages)  | | - Env & Profile Switcher    |
| - Update (GitHub release DL)   | | - XChaCha20Poly1305 Repo Sync |
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
    bin/              # Installed executable binaries (sagy, sagy-original)
    runtime/          # Optional local toolchains or runtimes
    tmp/              # Temporary download, extraction and repo-sync working trees
    accounts/         # Fixed, isolated credential slots for each validated account ID
    state.json        # Versioned account inventory, credential refs, active profile, and usage
    repo-sync.json    # Last synced repository configuration
  ```

## 3. Account Selection & Cooldown Policy

1. **Fail-closed eligibility**: Every candidate must have a compatible State v2 credential reference and a locally verified fixed credential slot. Zero quota, active cooldown, invalid authentication, permission failures, and transient failures are ineligible.
2. **Typed tiers**: A successful probe is `Primary`, a refreshable authorized-user credential is `Secondary`, and a locally verified but unprobed credential is `Fallback`. Small quota/plan/recency bonuses only order accounts inside those safety tiers.
3. **Stickiness**: The current account is retained only when it passes the same eligibility predicate as every other candidate.
4. **Automatic fallback**: Only a bounded, canonical Google JSON error from a failed `agy` child can establish `RESOURCE_EXHAUSTED`. The exact credential enters a bounded cooldown without further probes, and one launch can try at most three eligible accounts.

## 4. State and Credential Transactions

- One CLI invocation owns one exact `StateSession`; all mutations use revision-checked compare-and-swap commits.
- State stores credential references and digests, never credential payloads or caller-controlled credential paths.
- Credential files and the two active-home OAuth slots are published with durable journals before State commits. Recovery is receipt-bound and runs before later mutations.
- OAuth access tokens, OAuth authorized-user documents, API keys, and Vertex service accounts have mutually exclusive launch environments and fixed managed layouts.

## 5. Encrypted Account Pool Synchronization

- **Algorithm**: `XChaCha20Poly1305` authenticated encryption with Argon2id key derivation.
- **Key Source**: `SAGY_POOL_KEY` environment variable.
- **Payload Format**: Strict, bounded v2 bundle (`.sagy-account-pool/bundle.enc.json`) containing portable credential material, typed usage, and rollback watermarks.
- **Cross-Host Workflow**:
  - `sagy push <repo>`: Exports local accounts, encrypts into bundle, commits and pushes to Git.
  - `sagy pull <repo>`: Clones repository, decrypts bundle, merges accounts into local state, and refreshes usage cache.
