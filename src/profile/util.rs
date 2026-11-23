//! `profile` 子模块共用的无 panic 输出、有界读取与 shell 转义辅助函数。
use std::ffi::OsStr;
use std::io::{Read, Write};

use anyhow::{Context, Result, bail};

pub(super) fn write_stderr_line(msg: impl std::fmt::Display) {
    // 忽略下游管道提前关闭时的 EPIPE，避免 CLI 在管道消费场景下 panic。
    let _ = writeln!(std::io::stderr().lock(), "{msg}");
}

pub(super) fn write_stdout_line(msg: impl std::fmt::Display) {
    let _ = writeln!(std::io::stdout().lock(), "{msg}");
}

pub(super) fn shell_quote(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("Profile helper paths must be UTF-8.")?;
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

pub(super) fn bounded_read(mut reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("Profile helper input exceeds the {limit}-byte limit.");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn shell_quote_escapes_single_quotes_and_rejects_non_utf8() {
        assert_eq!(shell_quote(OsStr::new("a' b")).unwrap(), "'a'\\'' b'");
        assert!(shell_quote(OsStr::from_bytes(b"bad\xffpath")).is_err());
    }

    #[test]
    fn bounded_read_accepts_exact_limit_and_rejects_overflow() {
        assert_eq!(bounded_read(Cursor::new(b"abcd"), 4).unwrap(), b"abcd");
        assert!(bounded_read(Cursor::new(b"abcde"), 4).is_err());
    }
}
