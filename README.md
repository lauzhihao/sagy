# sagy

[English](./README.md) | [简体中文](./README.zh-CN.md)

`sagy` is a high-performance, cross-platform CLI launcher and smart account manager for Google Antigravity CLI (`agy`), built in Rust. It provides automated multi-account rotation, rate-limit cooldown management, and encrypted account pool synchronization via Git.

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

## 2. Installed Binaries

`sagy` installs convenient entrypoints in `$SAGY_HOME/bin`:

| Binary | Target Model & Mode |
| :--- | :--- |
| **`sagy`** | Default launcher, auto-selects healthiest account and starts `agy` (defaults to `gemini-3.7-flash-high`; switch other models inside agy) |
| **`sagy-original`** | Passthrough helper straight to official underlying `agy` |

---

## 3. Command Reference

Angle brackets `<>` mark required arguments, square brackets `[]` mark optional ones.

| Command | Action |
| :--- | :--- |
| `sagy` / `sagy launch [agy args...]` | Refresh usage, switch to best account, and launch Antigravity CLI |
| `sagy auto` | Select and switch to the best account without launching |
| `sagy list` | Print table of all accounts, plan types, health status, and cooldowns |
| `sagy refresh` | Immediately refresh all account health states |
| `sagy use <email\|id>` | Manually switch to a specified account |
| `sagy rm <email\|id>` | Remove a registered account |
| `sagy add` | Add a new account credential. Same credential flags as `login`, plus `--switch`; interactive when no credential flag is given |
| `sagy login` | Register or update one account credential. `--token` / `--api-key` are non-interactive; with neither flag, sagy prompts once and reads a token you already hold with hidden input |
| `sagy import-known` | Auto-discover and import existing `~/.gemini` credentials |
| `sagy import-auth <path>` | Import credentials from a JSON or token file |
| `sagy push [repo]` | Encrypt (XChaCha20Poly1305) and push account pool to a Git repository |
| `sagy pull [repo]` | Pull and decrypt account pool from a Git repository |
| `sagy update` | Check and self-update from GitHub Releases (alias: `sagy upgrade`) |
| `sagy -- <agy args...>` | Pass every remaining argument straight through to `agy` |

Any first token that is not a known subcommand is also passed through to `agy`.

### How `login` / `add` Obtain Credentials

`sagy login` and `sagy add` never open a browser and never run an OAuth authorization exchange.
Every mode only *accepts* a credential you already have:

- `--token <TOKEN>` / `--api-key <KEY>`: fully non-interactive.
- No credential flag (or an explicit `--oauth`): sagy prints
  `Paste your Antigravity OAuth Token (or Google Token):` and reads one line with echo disabled.
  There is no browser redirect, no authorization code, and no `client_id` / `client_secret` handshake.

sagy also never exchanges a `refresh_token` for a fresh access token. A `refresh_token` inside an
`authorized_user` document is stored, synchronized, and handed to `agy` unchanged; any refresh is
performed by `agy` itself against Google. When a probe reports an expired authorized-user
credential, sagy only marks the account as needing a refresh - it does not perform one.

### Session Resume

`sagy` and `sagy launch` append `--continue` to the `agy` argv, so the previous conversation is
resumed by default. Exactly two things suppress it:

1. `--no-resume`. It is a sagy-side flag, so it must appear before the first `agy` argument
   (`sagy --no-resume ...` or `sagy launch --no-resume ...`). Written after one, it is no longer a
   sagy flag: `sagy --yolo --no-resume` forwards `--no-resume` to `agy` and still resumes.
2. The `agy` arguments already carry a session intent of their own. In that case sagy adds nothing
   and lets `agy` decide. This triggers on any of:
   `-c`, `--continue`, `-p`, `--print`, `--print=<...>`, `--prompt`, `--prompt=<...>`,
   `-i`, `--prompt-interactive`, `--conversation`, `--conversation=<...>`,
   any bare token that does not start with `-`, or a `--` separator that is itself still part of
   the argument list handed to `agy` (everything after such a separator counts as well).
   The value following `--model` / `-m` is an option value, not a bare token, and does not count.

   A *leading* separator is consumed by sagy's own argument parsing and never reaches that check:
   `sagy -- --help` and `sagy launch -- --help` are judged only on `--help`, so they still resume.
   Pass `--no-resume` there if you want a fresh session. A separator that appears later, as in
   `sagy --yolo -- --help`, does reach `agy` and does suppress resuming.

Plain passthrough (`sagy <agy args...>`) follows the same rule: only `--no-resume` turns resuming
off, so adding an unrelated flag never silently changes session behaviour.

### Options

| Scope | Option | Meaning |
| :--- | :--- | :--- |
| Global | `--state-dir <path>` | Override the state root for this invocation (wins over `SAGY_HOME`) |
| `launch` | `--dry-run` | Preview the selected account without switching or launching |
| `launch` | `--no-launch` | Switch to the best account and exit without launching |
| `launch` | `--no-resume` | Do not resume the previous conversation session. Must be written before the first `agy` argument |
| `launch` | `--no-import-known` | Skip automatic discovery and import of local `~/.gemini` credentials |
| `launch` | `--takeover` | **Overwrites credentials in the active Antigravity home that sagy does not manage.** See "Security Escape Hatch: `--takeover`" below |
| `auto` | `--dry-run`, `--no-import-known`, `--takeover` | Same meaning as for `launch` |
| `use` | `--takeover` | Same meaning as for `launch` |
| `add` | `--switch` | Immediately switch to the account after adding |
| `add`, `login` | `--token <TOKEN>` | Raw OAuth / Antigravity token |
| `add`, `login` | `--api-key <KEY>` | Google Gemini API key |
| `add`, `login` | `--oauth` | Explicitly select the interactive token prompt (already the default when no credential flag is given). Conflicts with `--token` / `--api-key` / `--api` |
| `add`, `login` | `--api` | Accepted but inert: combined with `--api-key` it changes nothing, and on its own it can only fail with `When using --api, please also provide --api-key <KEY>`. Deprecated; pass `--api-key` alone instead |
| `add`, `login` | `--email <EMAIL>` | Associated email address for the account |
| `add`, `login` | `--project-id <ID>` | Google Cloud project ID (optional) |
| `add`, `login` | `--takeover` | Same meaning as for `launch` |
| `rm` | `-y`, `--yes` | Skip the confirmation prompt |
| `update` | `-f`, `--force` | Update even if the version already matches |
| `push`, `pull` | `--path <REPO_PATH>` | Subdirectory inside the repository (default: `.sagy-account-pool`) |
| `push`, `pull` | `-i <IDENTITY_FILE>` | SSH private key path for repository authentication |
| `push`, `pull` | `--insecure-host-key` | **Disables SSH host key verification.** See the warning in section 4 |

### Security Escape Hatch: `--takeover`

`sagy` never silently overwrites credentials it did not write. The two files it owns in the live
Antigravity home are `$ANTIGRAVITY_CONFIG_DIR/antigravity-oauth-token` and
`$GEMINI_HOME/oauth_creds.json`.

Two cases are distinguished, and only the second one needs you to do anything:

1. The file already there **is** one of your registered accounts (byte-for-byte identical). `sagy`
   adopts it in place, rewrites nothing, and the first `sagy` run on a machine that was already
   using Antigravity just works. No flag needed.
2. The file is something `sagy` does not recognise. The switch is refused, nothing on disk is
   touched, and the error names the command below.

`--takeover` is the explicit opt-in for case 2. It moves each replaced file aside to
`<name>.sagy-backup-<txid>` **in the same directory** before publishing the selected account, so the
credential it replaced always stays recoverable:

```bash
sagy launch --takeover
```

The same flag exists on `sagy auto`, `sagy use`, `sagy login`, and `sagy add`. If you prefer, back
the files up yourself and delete them instead - `sagy` then starts from an empty active home.

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

The bundle is encrypted with XChaCha20Poly1305 and an Argon2id-derived key, and is stored at
`<repo>/.sagy-account-pool/bundle.enc.json`.

### Repository Resolution Order

The repository used by `push` / `pull` is resolved in this order, first match wins:

1. The `[repo]` positional argument. When present it is also persisted to `repo-sync.json`.
2. The `last_repo` entry saved in `$SAGY_HOME/repo-sync.json` by a previous run.
3. The `SAGY_POOL_REPO` environment variable.

If none of the three yields a repository, the command fails and asks for a repository URL.
Note that a saved `repo-sync.json` therefore takes precedence over `SAGY_POOL_REPO`.

### Security Escape Hatch: `--insecure-host-key`

Host key verification is **enabled by default**: `sagy` does not weaken the SSH defaults, so an
unknown or changed host key aborts the transfer.

`--insecure-host-key` opts out of that by running git with
`ssh -o StrictHostKeyChecking=no`. It accepts whatever host key the server presents, which means a
man-in-the-middle can impersonate the remote and observe every push/pull of your account pool.
The bundle itself stays encrypted with `SAGY_POOL_KEY`, but the connection no longer proves who you
are talking to. The command prints an explicit warning to stderr whenever the flag is used.

Only use it for a repository you fully control on a trusted network, and prefer adding the host to
`~/.ssh/known_hosts` instead.

---

## 5. Environment Variables

| Variable | Used by | Effect |
| :--- | :--- | :--- |
| `SAGY_HOME` | CLI, installers | State and install root. Default `~/.sagy`. `--state-dir` overrides it |
| `SAGY_POOL_KEY` | `push`, `pull` | Passphrase for the encrypted account-pool bundle. Required for sync |
| `SAGY_POOL_REPO` | `push`, `pull` | Fallback repository, used only when no argument and no saved `repo-sync.json` |
| `SAGY_UPDATE_REPO` | `update` | GitHub `owner/repo` to fetch releases from. Default `lauzhihao/sagy` |
| `ANTIGRAVITY_CONFIG_DIR` | CLI | Overrides the live Antigravity CLI home. Default `~/.gemini/antigravity-cli` |
| `GEMINI_HOME` | CLI | Overrides the live Gemini home. Default `~/.gemini` |
| `AGY_BIN` | `launch`, passthrough | Explicit path to the `agy` binary. Checked before every other lookup |
| `LC_ALL`, `LC_MESSAGES`, `LANG` | CLI | A `zh*.UTF-8` locale selects Chinese console output; anything else is English |

Installer-only variables:

| Variable | Script | Effect |
| :--- | :--- | :--- |
| `SAGY_REPO` | `install.sh` | GitHub `owner/repo` to download from. Default `lauzhihao/sagy` |
| `SAGY_VERSION` | `install.sh` | Install a specific tag instead of the latest release |
| `INSTALL_BIN` | `install.sh` | Destination directory for the binaries. Default `$SAGY_HOME/bin` |
| `SAGY_CURL_CONNECT_TIMEOUT` | `install.sh` | curl connect timeout in seconds. Default `10` |
| `SAGY_CURL_MAX_TIME` | `install.sh` | curl total timeout in seconds. Default `120` |
| `SAGY_DOWNLOAD_TIMEOUT_SEC` | `install.ps1` | Download timeout in seconds. Default `120` |

### Environment Handed To The `agy` Child

The child `agy` process inherits the parent environment, except that every launch first clears the
three authentication variables below so a parent shell or a previously selected account cannot
contribute credentials. Each is then re-set only when the selected account actually needs it:

| Variable | Always cleared before launch | Re-set by sagy when |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` | yes | the selected account is an API-key account |
| `GOOGLE_APPLICATION_CREDENTIALS` | yes | the selected account is a Vertex service account |
| `GOOGLE_CLOUD_PROJECT` | yes | the account carries a project ID (OAuth and Vertex accounts) |

The list is an explicit deny-list of exactly these three names. Any other Google-related variable
in your shell (for example `GOOGLE_API_KEY` or `GOOGLE_GENAI_USE_VERTEXAI`) is inherited by `agy`
unchanged, so unset it yourself if it must not influence the child.

`ANTIGRAVITY_CONFIG_DIR` and `GEMINI_HOME` are also the credential sandbox used when developing:
point both at a scratch directory before running `cargo test`, otherwise the test suite writes over
the real credentials in your `~/.gemini`.

---

## 6. Runtime Directory Layout

The state root defaults to `~/.sagy` and can be relocated with `SAGY_HOME` or `--state-dir`:

```text
~/.sagy/
  bin/              # Installed executables (sagy, sagy-original)
  accounts/         # Isolated credential slot per managed account
  runtime/          # Optional local toolchains or runtimes
  tmp/              # Temporary download, extraction and repo-sync working trees
  state.json        # Account inventory, credential refs, active profile, usage cache
  repo-sync.json    # Last synced repository configuration
```

---

## 7. License

MIT License
