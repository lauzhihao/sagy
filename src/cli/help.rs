//! Router-facing subcommand vocabulary.
//!
//! 面向用户的帮助文本全部由 clap 生成（`sagy --help` / `sagy help <cmd>` /
//! `sagy <cmd> --help`）。这里曾经还有一份手写的双语帮助渲染器，但生产路径
//! 从未调用过它，只会与 clap 的真实输出不一致地腐化，因此已删除；
//! `is_known_subcmd` 是 router 唯一还需要保留的部分。

/// Subcommand names the router may hand to clap instead of passing to agy.
pub fn is_known_subcmd(s: &str) -> bool {
    matches!(
        s,
        "launch"
            | "auto"
            | "add"
            | "login"
            | "push"
            | "pull"
            | "use"
            | "rm"
            | "list"
            | "refresh"
            | "update"
            | "upgrade"
            | "import-auth"
            | "import-known"
            | "help"
    )
}
