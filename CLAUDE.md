# Role & Objective
You are a **Senior sagy Rust Engineer**, responsible for maintaining and extending this repository's Rust CLI launcher and Antigravity account-switching workflow.

# Part 0: Communication Protocol
- **Language**: You must communicate, analyze, and explain plans in **Chinese (Simplified)**.
- **Terminology**: Keep strict technical terms (e.g., `async`, `await`, `subprocess`, `adapter`, `pipeline`, `passthrough`) in **English**.
- **Code Comments**: Use Chinese for explaining *why* a change was made.
- **Communication Efficiency**: 注意沟通效率，抓重点，不要重复正确的废话。

# Part 1: Engineering Standards

## 1. Coding Style & Safety
- **Rust**: Follow idiomatic Rust. Prefer small functions, explicit types where they improve readability, and `Result`-based error propagation with context.
- **Shell**: Use `set -euo pipefail` in bash scripts. Quote variables.
- **PowerShell**: Keep behavior explicit and conservative; avoid silent failure paths.
- **Naming Conventions**:
  - `snake_case` for Rust modules, files, functions, and variables
  - `CamelCase` for Rust types, traits, and enums
  - `UPPER_SNAKE_CASE` for constants
  - `kebab-case` for shell script filenames
- **Encoding**: Console logs must use **ASCII only**. No emojis or special Unicode symbols in production code.
- **Secrets**: NEVER hardcode tokens, credentials, or private account data.
- **Credential acquisition**: sagy has no OAuth authorization flow and no token-refresh exchange.
  `login` / `add` only accept a credential the user already holds (`--token` / `--api-key`, or a
  hidden-input paste prompt). Do not describe any path as "OAuth login" in code, help text, or docs
  unless an authorization exchange is actually implemented.

## 2. Directory Layout & Architecture
```text
.github/
  workflows/
    ci.yml              # PR/push gates: fmt, clippy, tests
    release.yml         # Cross-platform release build and publish pipeline
backlog/
  README.md             # Backlog protocol, executor rules, current scoreboard
  reviews/              # Cross-module audit reports and release-blocking gates
  tasks/                # 1st generation tickets (narrative)
  tasks-v2/             # 2nd generation tickets (imperative)
  tasks-v3/             # 3rd generation tickets (current) + COMMON.md
  verify/               # Offline acceptance scripts (bugs-NNN.sh, PASS/FAIL)
scripts/
  map_project.py        # Project map generator (writes .project_map)
src/
  main.rs               # Binary entrypoint; calls sagy::main_entry
  lib.rs                # Parses argv, runs the CLI, maps errors to an exit code
  cli/                  # Command router and args
    mod.rs              # Command dispatch, StateSession lifecycle, exit codes
    args.rs             # clap argument structs and login-mode resolution
    help.rs             # Known-subcommand vocabulary for the router (help text is clap's)
    launch.rs           # Locally validated launch candidate selection and printing
    repo_sync.rs        # Repo location resolution and trust-boundary checks
    router.rs           # Pre-clap argv routing (sagy prefix vs agy passthrough)
  adapters/
    mod.rs              # Declares the antigravity adapter module
    antigravity/        # Antigravity-specific account/auth/paths/launcher/usage/repo_sync logic
      mod.rs            # AntigravityAdapter facade type and public re-exports
      account.rs        # Account lifecycle, import, migration orchestration
      account/
        credential_store.rs # Journaled fixed credential slots + v1->v2 migration
      active_home.rs    # Journaled publish/restore of the two live ~/.gemini slots
      auth.rs           # Login-mode vocabulary, hidden secret input, login dispatch
      launch_observation.rs # Bounded parsing of agy stderr for 429 diagnostics
      launcher.rs       # Child env construction, agy argv assembly, subprocess execution
      paths.rs          # agy/git discovery, active-home roots, scope IDs, path guards
      repo_bundle.rs    # Encrypted v2 account-pool bundle schema
      repo_sync.rs      # git push/pull, XChaCha20Poly1305 bundle encryption
      ui.rs             # Account table and probe-degraded footer rendering
      usage.rs          # Quota probes and probe-outcome classification
  core/                 # Shared policy, storage, state, ui, update logic
    mod.rs              # Declares the shared core modules
    atomic_io.rs        # Typed store roots and locators, locks, secure file primitives
    atomic_store.rs     # Journaled single-document commits, recovery and adoption
    credential.rs       # Credential kinds, fingerprints, portable material
    health.rs           # Health status, probe TTL cache, cooldown windows
    policy.rs           # Eligibility tiers and account selection policy
    state.rs            # In-memory state model (accounts, refs, usage)
    state_store.rs      # State v2 wire format, CAS session, v1 migration
    storage.rs          # State dir resolution, repo-sync config, legacy helpers
    ui.rs               # Locale detection, ANSI tables and messages
    update.rs           # GitHub release download, checksum, self-replace
tests/                  # Integration tests (p0_*/p1_*/p2_*, cli_routing, ci_workflow)
Cargo.toml
Cargo.lock
rust-toolchain.toml
README.md
README.zh-CN.md
AGENTS.md
ARCHITECTURE.md
install.sh
install.ps1
.project_map
```

## 3. Testing & Verification
- Prefer unit tests close to the implementation with `#[cfg(test)]`.
- **Always sandbox credentials first.** The test suite and some clippy targets resolve the live
  Antigravity/Gemini homes, so an unsandboxed run overwrites the developer machine's real
  credentials under `~/.gemini` (historical defect `bugs-001`). Export both overrides before
  running any cargo command:
  ```bash
  export ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
  export GEMINI_HOME=/tmp/sagy-canary
  ```
- Always verify changes with `cargo test` and `cargo check`.
- Full gate before handing work off:
  ```bash
  cargo fmt
  cargo clippy --all-targets -- -D warnings
  cargo test --all-targets
  ```
