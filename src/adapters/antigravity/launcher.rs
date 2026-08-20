use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use super::paths::find_agy_bin;
use crate::core::state::AccountRecord;

impl super::AntigravityAdapter {
    pub fn launch_agy(
        &self,
        state_dir: &Path,
        account: &AccountRecord,
        extra_args: &[OsString],
        resume: bool,
    ) -> Result<i32> {
        let agy_bin = find_agy_bin(Some(state_dir))
            .ok_or_else(|| anyhow::anyhow!("Antigravity CLI (agy) binary not found in PATH or standard locations"))?;

        // 1. Prepare base command
        let mut cmd = Command::new(&agy_bin);

        // 2. Inject environment variables based on account
        if let Some(api_key) = &account.api_key {
            cmd.env("GEMINI_API_KEY", api_key);
        }
        if let Some(project_id) = &account.project_id {
            cmd.env("GOOGLE_CLOUD_PROJECT", project_id);
        }

        // 3. Inspect binary alias invocation for model shortcuts
        let mut final_args = Vec::new();
        if let Some(exe_name) = env::args().next().and_then(|p| {
            Path::new(&p)
                .file_name()
                .and_then(|s| s.to_str())
                .map(ToString::to_string)
        }) {
            let exe_lower = exe_name.to_ascii_lowercase();
            if (exe_lower.contains("flash") || exe_lower == "sagy-flash")
                && !contains_flag(extra_args, "--model")
            {
                final_args.push(OsString::from("--model"));
                final_args.push(OsString::from("gemini-3.7-flash"));
                if !contains_flag(extra_args, "--effort") {
                    final_args.push(OsString::from("--effort"));
                    final_args.push(OsString::from("low"));
                }
            } else if (exe_lower.contains("pro") || exe_lower == "sagy-pro")
                && !contains_flag(extra_args, "--model")
            {
                final_args.push(OsString::from("--model"));
                final_args.push(OsString::from("gemini-3.7-pro"));
                if !contains_flag(extra_args, "--effort") {
                    final_args.push(OsString::from("--effort"));
                    final_args.push(OsString::from("high"));
                }
            } else if (exe_lower.contains("think") || exe_lower == "sagy-think")
                && !contains_flag(extra_args, "--model")
            {
                final_args.push(OsString::from("--model"));
                final_args.push(OsString::from("gemini-3.7-flash"));
                if !contains_flag(extra_args, "--effort") {
                    final_args.push(OsString::from("--effort"));
                    final_args.push(OsString::from("high"));
                }
            }
        }

        // 4. Session continuation / resume logic
        if resume
            && !contains_flag(extra_args, "--continue")
            && !contains_flag(extra_args, "-c")
            && !contains_flag(extra_args, "--prompt")
            && !contains_flag(extra_args, "-p")
            && !contains_flag(extra_args, "--conversation")
        {
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
