# bugs-010 alias 二进制吞掉所有 sagy 子命令，--continue 注入两条路径不一致

- 严重度: P2 (行为 / 文档)
- 状态: 待确认设计意图
- 引入版本: 2c5e976

## 现象一：alias 无法执行任何 sagy 子命令

`src/cli/mod.rs:133-165` 的 `rewrite_alias_args` 把除 `--state-dir` 和
5 个 launch flag 之外的一切参数都塞进 `extra_args`，转发给 agy。实测：

```text
$ flash list
AGY_ARGV: --model gemini-3.7-flash --effort low --continue list

$ flash update
AGY_ARGV: --model gemini-3.7-flash --effort low --continue update

$ flash rm a@example.com -y
AGY_ARGV: --model gemini-3.7-flash --effort low --continue rm a@example.com -y
```

`flash --version` 和 `flash --help` 例外（被更早的分支拦截）。

如果这是有意设计（alias 就是纯启动器），需要在 README 与 help 中写明
"alias 入口不接受 sagy 子命令"，否则 `flash update` 静默不更新会误导用户。

## 现象二：--continue 注入不一致

| 调用 | 实际传给 agy |
| :--- | :--- |
| `sagy` | `--continue` |
| `sagy "write a test"` | `write a test`（无 --continue） |
| `flash` | `--model ... --effort low --continue` |
| `flash "write a test"` | `--model ... --effort low --continue write a test` |

`sagy <prompt>` 走 `Passthrough` 分支，`run_passthrough` 硬编码 `resume=false`
（`src/adapters/antigravity/launcher.rs:111`）；
`flash <prompt>` 走 `launch` 分支，`resume=true`。
同一个"带 prompt 启动"语义，两条路径行为相反。

而且 `--continue`（继续上一轮对话）与"带一个新 prompt"在语义上是冲突的，
`flash "..."` 这条大概率是错的。

## 现象三：--print 未被排除

`launcher.rs:74-80` 的排除清单包含 `--continue` / `-c` / `--prompt` / `-p` /
`--conversation`，但漏了 `--print`。而 `agy --help` 显示
`--prompt` 是 `--print` 的别名、`-p` 是 `--print` 的短选项，
所以直接写 `--print` 时仍会被注入 `--continue`。
同理 `-i` / `--prompt-interactive` 也未排除。

## 修复方案

1. 明确 alias 的定位并落到文档；若希望 alias 也能跑子命令，
   在 `rewrite_alias_args` 中先用 `is_known_subcmd`（`src/cli/help.rs` 已有该函数）
   判断第一个非 flag 参数，命中则按正常子命令路由。
   **若采用此方案，必须先修 bugs-009。**
2. 统一 resume 语义：`extra_args` 非空（即用户给了 prompt）时不注入 `--continue`，
   `sagy` 与 alias 两条路径共用同一判断。
3. 排除清单补齐 `--print`、`-i`、`--prompt-interactive`。
4. 消除 `rewrite_alias_args` 与 `rewrite_passthrough_launch_args` 的重复
   （两个函数目前逐字节相同，见 bugs-012）。

## 验收标准

- [ ] `sagy <prompt>` 与 `flash <prompt>` 的 resume 行为一致
- [ ] `flash --print "x"` 不会被注入 `--continue`
- [ ] alias 的子命令行为与文档描述一致
