//! 桌面账号导入接口；实现由独立工作包补齐。
use std::path::{Path, PathBuf};

use anyhow::Result;

pub(super) struct Candidate;
pub(super) struct Importer;
pub(super) enum ImportOutcome {
    Added(String),
    AlreadyRegistered(String),
    Superseded,
    Busy,
}

pub(super) fn read_candidate(_path: &Path) -> Result<Option<Candidate>> {
    anyhow::bail!("Desktop account import implementation is pending.")
}

impl Candidate {
    pub(super) fn fingerprint(&self) -> [u8; 32] {
        unreachable!("No candidate is constructed by the interface scaffold")
    }
}

impl Importer {
    pub(super) fn new(_root: PathBuf, _token_path: PathBuf) -> Result<Self> {
        anyhow::bail!("Desktop account import implementation is pending.")
    }
    pub(super) fn import(&mut self, _candidate: Candidate) -> Result<ImportOutcome> {
        anyhow::bail!("Desktop account import implementation is pending.")
    }
}
