# R9 CLI 表面复核回归

先读 `backlog/tasks-v3/round2/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round2/R9`

## 归属文件

- `src/cli/args.rs`
- `src/cli/mod.rs`
- `src/cli/router.rs`
- `src/cli/help.rs`
- `tests/p2_cli_surface.rs`
- `tests/cli_routing.rs`

## R9-1 `--` 边界的 resume 行为与交付说明不符

第一轮交接给文档的 resume 规则里写着"`--` 边界即开新会话"，但 router 在两条路径上都吃掉了 `--`，
该分支从真实 CLI 输入不可达；同时 `sagy -- --version` 本次由"不注入"变成了"注入 --continue"。

- AC-R9-1.1 确定并实现一条真实可达的规则，让 `--` 边界的行为与文档描述一致。
- AC-R9-1.2 `sagy -- --version` 的行为必须有测试固定，并在报告里说明它现在是什么、为什么。

## R9-2 `--oauth` 的读取是装饰性的

`--oauth` 在任何可达输入下与函数末尾的 fallback 返回完全相同的值，真正生效并被测试的只有 clap 互斥报错。

- AC-R9-2.1 要么让它在某个可达输入上产生可观察差异并测试之，
  要么只保留 clap 互斥、删掉那段装饰性读取并说明理由。

## R9-3 help 与死字段检查的覆盖缺口

- AC-R9-3.1 `--all` 从 help 中消失只验证了 push，补上 pull。
- AC-R9-3.2 给 push/pull/list/refresh/import-known 补的 `#[command(about=..)]` 没有任何测试守护，
  全部删掉 15 个新测试仍全绿。补一个断言真实 help 输出的用例。
- AC-R9-3.3 "声明但从不读取"的静态检查用的是标识符出现次数 >= 2，
  对与常见标识符同名的字段恒为真。换一个能真正发现新死字段的判据，
  并用一个人为构造的死字段验证它会报警（验证完删掉）。
