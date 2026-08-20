use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use super::paths::find_agy_bin;
use crate::core::state::AccountRecord;

// agy models 的真实标识。effort 烧在 ID 内, 不再单独传 --effort。
pub const DEFAULT_MODEL_ID: &str = "gemini-3.7-flash-high";

impl super::AntigravityAdapter {
    pub fn launch_agy(
        &self,
        state_dir: &Path,
        account: &AccountRecord,
        extra_args: &[OsString],
        resume: bool,
    ) -> Result<i32> {
        let agy_bin = find_agy_bin(Some(state_dir)).ok_or_else(|| {
            anyhow::anyhow!("Antigravity CLI (agy) binary not found in PATH or standard locations")
        })?;

        // 1. Prepare base command
        let mut cmd = Command::new(&agy_bin);

        // 2. Inject environment variables based on account
        if let Some(api_key) = &account.api_key {
            cmd.env("GEMINI_API_KEY", api_key);
        }
        if let Some(project_id) = &account.project_id {
            cmd.env("GOOGLE_CLOUD_PROJECT", project_id);
        }

        // 3. 注入默认模型。用户显式指定 --model 时不覆盖。
        let mut final_args = Vec::new();
        if !contains_flag(extra_args, "--model") {
            final_args.push(OsString::from("--model"));
            final_args.push(OsString::from(DEFAULT_MODEL_ID));
        }

        // 4. Session continuation / resume logic: only inject --continue if no prompt or continuation flag is given
        if resume && !has_prompt_or_continue_args(extra_args) {
            final_args.push(OsString::from("--continue"));
        }

        // Append user extra args
        final_args.extend_from_slice(extra_args);
        cmd.args(&final_args);

        // 5. Stdio inheritance for interactive TUI
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn `{}`", agy_bin.display()))?;

        let status = child
            .wait()
            .with_context(|| format!("failed to wait on `{}`", agy_bin.display()))?;

        let code = status.code().unwrap_or(0);
        Ok(code)
    }

    pub fn run_passthrough(
        &self,
        state_dir: &Path,
        account: &AccountRecord,
        args: &[OsString],
    ) -> Result<i32> {
        self.launch_agy(state_dir, account, args, false)
    }
}

fn contains_flag(args: &[OsString], flag: &str) -> bool {
    args.iter()
        .any(|arg| arg.to_string_lossy().eq_ignore_ascii_case(flag))
}

fn has_prompt_or_continue_args(extra_args: &[OsString]) -> bool {
    let mut has_positional = false;
    for arg in extra_args {
        let s = arg.to_string_lossy();
        if s == "--continue"
            || s == "-c"
            || s == "--prompt"
            || s == "-p"
            || s == "--print"
            || s == "-i"
            || s == "--prompt-interactive"
            || s == "--conversation"
            || s.starts_with("--prompt=")
            || s.starts_with("--print=")
            || s.starts_with("--conversation=")
        {
            return true;
        }
        if !s.starts_with('-') {
            has_positional = true;
        }
    }
    has_positional
}
