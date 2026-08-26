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
               | (router.rs, args.rs, launch.rs,  |
               |  repo_sync.rs, help.rs)          |
               +-----------------+----------------+
                                 |
                 +---------------+---------------+
                 |                               |
                 v                               v
+--------------------------------+ +-----------------------------+
|          Core Engine           | |     Antigravity Adapter     |
| - State v2 (CAS transactions)  | | - Binary Discovery (agy)    |
| - Atomic IO / journaled store  | | - OAuth/API/Vertex Model    |
| - Health probes and cooldowns  | | - Active-home Switcher      |
| - Policy (eligibility tiers)   | | - Launch Observation (429)  |
| - UI (ANSI tables & messages)  | | - XChaCha20Poly1305 Repo Sync |
| - Update (GitHub release DL)   | |                             |
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

## 2. Source Layout & Module Responsibilities

```text
src/
  main.rs                  Binary entrypoint; calls sagy::main_entry
  lib.rs                   Parses argv, runs the CLI, maps errors to an exit code
  cli/
    mod.rs                 Command dispatch, StateSession lifecycle, exit codes
    router.rs              Pre-clap argv routing: sagy prefix vs agy passthrough
    args.rs                clap argument structs and login-mode resolution
    launch.rs              Locally validated launch candidate selection and printing
    repo_sync.rs           Repo location resolution and trust-boundary checks
    help.rs                Known-subcommand vocabulary for the router (help text is clap's)
  adapters/
    mod.rs                 Declares the antigravity adapter module
    antigravity/
      mod.rs               AntigravityAdapter facade type and public re-exports
      account.rs           Account lifecycle, import, migration orchestration
      account/
        credential_store.rs  Journaled fixed credential slots; v1 -> v2 migration
      active_home.rs       Journaled publish/restore of the two live ~/.gemini slots
      auth.rs              Login-mode vocabulary, hidden secret input, login dispatch
      launch_observation.rs Bounded parsing of agy stderr into launch diagnostics
      launcher.rs          Child env construction, agy argv assembly, subprocess run
      paths.rs             agy/git discovery, active-home roots, scope IDs, path guards
      repo_bundle.rs       Encrypted v2 account-pool bundle schema
      repo_sync.rs         git push/pull plus bundle encryption and merge
      ui.rs                Account table and probe-degraded footer rendering
      usage.rs             Quota probes and probe-outcome classification
  core/
    mod.rs                 Declares the shared core modules
    atomic_io.rs           Typed store roots and locators, locks, secure file primitives
    atomic_store.rs        Journaled single-document commits, recovery and adoption
    credential.rs          Credential kinds, fingerprints, portable material
    health.rs              Health status, probe TTL cache, cooldown windows
    policy.rs              Eligibility tiers and account selection policy
    state.rs               In-memory state model (accounts, refs, usage)
    state_store.rs         State v2 wire format, CAS session, v1 migration
    storage.rs             State dir resolution, repo-sync config, legacy helpers
    ui.rs                  Locale detection, ANSI tables and messages
    update.rs              GitHub release download, checksum, self-replace
tests/                     Integration tests (p0_*/p1_*/p2_*, cli_routing, ci_workflow)
```

## 3. Runtime Directory Layout & State Resolution

- **State root resolution**, first match wins: `--state-dir <path>`, then `SAGY_HOME`, then the
  platform default `~/.sagy`.
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
- The two live Antigravity homes are separate from the state root and are overridable on their own:
  `ANTIGRAVITY_CONFIG_DIR` (default `~/.gemini/antigravity-cli`) and `GEMINI_HOME` (default
  `~/.gemini`).
- **Child environment deny-list**: `launcher::configure_auth_environment` starts every launch by
  removing the complete authentication surface maintained by `core::credential`:
  `CLOUDSDK_AUTH_ACCESS_TOKEN`, `CLOUDSDK_CORE_PROJECT`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`,
  `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CLOUD_ACCESS_TOKEN`, `GOOGLE_CLOUD_LOCATION`,
  `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_QUOTA_PROJECT`, `GOOGLE_GENAI_USE_GCA`,
  `GOOGLE_GENAI_USE_VERTEXAI`, and `GOOGLE_OAUTH_ACCESS_TOKEN`. It then rebuilds only
  `GEMINI_API_KEY` for API-key accounts, `GOOGLE_APPLICATION_CREDENTIALS` for Vertex service
  accounts, `GOOGLE_CLOUD_PROJECT` when the OAuth or Vertex account carries a project ID, and a
  syntactically sanitized inherited `GOOGLE_CLOUD_LOCATION`. All other listed variables remain
  absent from the child.

## 4. Credential Acquisition Boundary

sagy has no OAuth authorization implementation and no token-refresh implementation. `login` / `add`
only *accept* an existing credential: `--token` / `--api-key` non-interactively, or a hidden-input
prompt (`auth.rs`) into which the user pastes a token they already hold. A `refresh_token` inside an
`authorized_user` document is stored, transported and handed to `agy` unchanged; `agy` performs any
refresh against Google. `health.rs` can only classify a credential as `RefreshRequired` - it never
refreshes one.

Google `authorized_user` material requires `client_id`, `client_secret`, and `refresh_token`.
`token_uri` is optional at the ingestion boundary and is canonicalized internally to the exact
`https://oauth2.googleapis.com/token` endpoint. Any explicitly different endpoint is rejected
fail-closed. Adoption and import preserve the original active-home bytes; portable material and
repo bundles serialize the canonical form, so omitted and canonical input have the same
fingerprint.

## 5. Account Selection & Cooldown Policy

1. **Fail-closed eligibility**: Every candidate must have a compatible State v2 credential reference and a locally verified fixed credential slot. Zero quota, active cooldown, invalid authentication, permission failures, and explicit service rejection are ineligible.
2. **Typed tiers**: A successful probe is `Primary`, a refreshable authorized-user credential is `Secondary`, and a locally verified but unprobed credential is `Fallback`. A locally validated credential whose probe channel failed through timeout, DNS, connection, proxy, or gateway errors is still selectable as the lowest `Degraded` tier. Small quota/plan/recency bonuses only order accounts inside those safety tiers.
3. **Stickiness**: The current account is retained only when it passes the same eligibility predicate as every other candidate.
4. **Automatic fallback**: Only a bounded, canonical Google JSON error from a failed `agy` child can establish `RESOURCE_EXHAUSTED`. The exact credential enters a bounded cooldown without further probes, and one launch can try at most three eligible accounts.

## 6. Launch Argument Composition & Session Resume

`launcher::final_launch_args` builds the exact argv appended after the resolved `agy` executable,
from two independent decisions plus the user's own arguments:

1. **Default model**: `--model gemini-3.7-flash-high` is prepended unless the user already passed
   `--model` / `-m` (long or `=` form).
2. **Session resume**: `--continue` is prepended only when both rules below allow it - the caller
   still asked to resume, and the `agy` arguments carry no session intent of their own.
   - **Rule 1 - resume by default.** The caller asks to resume unless it opts out. Only the
     explicit sagy-side `--no-resume` flag turns it off. `router::LAUNCH_SHORTCUT_FLAGS` only
     recognises it as a prefix, so it must precede the first `agy` argument; written later it is
     forwarded to `agy` verbatim and resuming still happens. Plain passthrough
     (`Command::Passthrough`) is routed through the same `run_launch` with `resume = true`, so
     adding an unrelated sagy flag can never change session behaviour.
   - **Rule 2 - never stack on an existing session intent.** If the arguments destined for `agy`
     already carry a session intent, sagy adds nothing and lets `agy` decide.
     `launcher::has_prompt_or_continue_args` reports that intent for any of:
     `-c`, `--continue`, `-p`, `--print`, `--print=<...>`, `--prompt`, `--prompt=<...>`, `-i`,
     `--prompt-interactive`, `--conversation`, `--conversation=<...>`, any token not starting with
     `-`, or a `--` separator present in `extra_args` together with everything after it. The value
     following `--model` / `-m` is consumed as an option value and is therefore not treated as a
     bare prompt token.
     Note the asymmetry of the separator: `router::route` strips a *leading* `--` before building
     `Route::Passthrough`, and clap strips it again for `launch -- <args>`, so `sagy -- --help`
     reaches `has_prompt_or_continue_args` as just `["--help"]` and still resumes. A separator in a
     later position (`sagy --yolo -- --help`) survives into `extra_args` and does suppress resuming.

The user's own arguments are always appended last, so `agy`'s own precedence rules decide when both
an injected and a user-supplied form of the same option are present.

## 7. State and Credential Transactions

- One CLI invocation owns one exact `StateSession`; all mutations use revision-checked compare-and-swap commits.
- State stores credential references and digests, never credential payloads or caller-controlled credential paths.
- Credential files and the two active-home OAuth slots are published with durable journals before State commits. Recovery is receipt-bound and runs before later mutations.
- OAuth access tokens, OAuth authorized-user documents, API keys, and Vertex service accounts have mutually exclusive launch environments and fixed managed layouts.

## 8. Encrypted Account Pool Synchronization

- **Algorithm**: `XChaCha20Poly1305` authenticated encryption with Argon2id key derivation.
- **Key Source**: `SAGY_POOL_KEY` environment variable.
- **Repository Source**: positional argument, then `repo-sync.json`, then `SAGY_POOL_REPO`.
- **Payload Format**: Strict, bounded v2 bundle (`.sagy-account-pool/bundle.enc.json`) containing portable credential material, typed usage, and rollback watermarks.
- **Transport**: the official `git` binary. Host key verification follows the SSH defaults; the
  opt-in `--insecure-host-key` flag is the only path that disables it, and it warns on stderr.
- **Cross-Host Workflow**:
  - `sagy push [repo]`: Exports local accounts, encrypts into bundle, commits and pushes to Git.
  - `sagy pull [repo]`: Clones repository, decrypts bundle, merges accounts into local state, and refreshes usage cache.

## 9. CI and Release Boundary

- Every GitHub Actions job that invokes Cargo first runs
  `.github/actions/setup-sagy-sandbox/action.yml`. The composite action derives isolated
  `HOME`, `SAGY_HOME`, `GEMINI_HOME`, `ANTIGRAVITY_CONFIG_DIR`, and `CARGO_HOME` paths at runner
  runtime and creates those directories before Rust toolchain setup.
- CI runs the Rust quality gate on Linux and the Windows runtime/checksum harness on a native
  Windows runner. Release builds depend on the version guard, quality job, and Windows harness.
- The publish job alone receives `contents: write`; third-party Actions are pinned to commit SHAs.
- No GitHub Release exists yet. Source builds are the current installation path; installer and
  updater downloads become usable only after the first separately approved tag/release.
