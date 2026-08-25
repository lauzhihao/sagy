# T7 CLI 表面：死参数、死帮助、resume 语义（P2/P3）

先读 `backlog/tasks-v3/COMMON.md`。
背景见审计报告的 HELP-001，以及 P3 的 `--all`、`login --oauth`、bugs-010（`--continue` 注入不一致）。

## 归属文件（只能改这些）

- `src/cli/args.rs`
- `src/cli/mod.rs`
- `src/cli/router.rs`
- `src/cli/help.rs`
- `src/cli/launch.rs`
- 新建：`tests/p2_cli_surface.rs`

**唯一的越界许可**：删除 `--all` 时你必须同时删掉
`src/adapters/antigravity/repo_sync.rs` 里的 `include_all` 字段才能编译。
这一处允许你改，但**只允许改这个字段相关的行**，不要碰该文件的任何其它内容。

不要修改既有的 `tests/cli_routing.rs`，除非某条断言与你的修复语义直接冲突；
真冲突时在报告里单独说明是哪一条、为什么。

## AC-1（P3）删除只接收不生效的参数

- AC-1.1 `--all` 从 push/pull 的参数表、help 文本和所有传递链路中删除。
  `sagy push --all <repo>` 之后必须报未知参数错误（clap 行为），而不是静默接受。
- AC-1.2 `login`/`add` 的 `--oauth` 要么真正生效（显式指定时强制走 OAuth 分支，
  与 `--api-key` 同时出现时报冲突），要么删除。选哪个都要在报告里说明理由。
- AC-1.3 全库不得再有"声明了参数但从不读取"的 CLI 字段。给出你的检查方法。

## AC-2（P2）删除不可达的帮助实现

`src/cli/help.rs` 的 `render_help` / `render_topic_help` 已无任何生产调用方，
用户看到的是 clap 生成的英文帮助，那 ~110 行双语文本对用户不可见。

- AC-2.1 删除死实现及其只断言自身的单测。保留 `is_known_subcmd` 等仍被 router 使用的项。
- AC-2.2 删除之后 `sagy --help`、`sagy help launch`、`sagy push --help` 必须仍能输出真实的参数说明。
- AC-2.3 `--state-dir` 这个全局参数必须在真实 help 输出里有说明文字（现在没有）。
- AC-2.4 `--` 之后的参数必须原样透传给 agy，`sagy launch -- --help` 不得被 sagy 截获。

## AC-3（P3）resume 语义必须可预测

现状：`sagy --model custom` 不注入 `--continue`（新会话），
而 `sagy --no-import-known --model custom` 会注入 `--continue`（续上一轮）——
加一个与会话无关的 flag 就改变了会话续接行为。

- AC-3.1 是否续接上一轮会话，必须只由一条明确的规则决定，且该规则与"用户额外传了哪些
  与会话无关的 sagy flag"无关。
- AC-3.2 在报告里写清你选定的规则（例如"带 prompt 即新会话，不带 prompt 即续接"），
  并说明它与 README 描述是否一致；不一致时列出需要 T9 同步的文档位置。
- AC-3.3 既有 `tests/cli_routing.rs` 里固化了旧行为的断言，若与新规则冲突，
  在报告里逐条列出并说明处理方式。

## AC-4（P2）router 参数解析矩阵

- AC-4.1 `--version` / `--help` 出现在任意位置都不得加载 state、不得切换凭据、不得启动子进程。
- AC-4.2 `sagy --prompt list`、`sagy --model custom`、`sagy --model=custom`、裸 prompt、
  `--` 边界、已知子命令，六种输入的路由结果必须有测试固定。

## 自检

除通用门禁外，AC-2.2 / AC-2.3 / AC-4.1 必须给出真实二进制的输出片段。
