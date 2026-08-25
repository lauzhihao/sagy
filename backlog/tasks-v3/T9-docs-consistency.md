# T9 文档与实现一致性（P2/P3）

先读 `backlog/tasks-v3/COMMON.md`。
背景见审计报告的 DOC-001 以及 P3 的文档一组。

## 归属文件（只能改这些）

- `README.md`
- `README.zh-CN.md`
- `ARCHITECTURE.md`
- `CLAUDE.md`
- `AGENTS.md`
- `.project_map`
- `backlog/README.md`（**这是 COMMON.md 那条"不得改 backlog/"的唯一例外**）

**不得修改任何 `src/` 或 `tests/` 文件。** 你只描述代码，不改代码。

## 重要前提

其它 8 个工单正在并行修改行为。因此：

- 只写你**读代码能确认的当前事实**，以及那些不会被其它工单改变的内容。
- 遇到明显正在被修的行为（429 降级的可达性、离线可用性、`--all`、resume 语义、
  bundle 迁移），不要写死具体行为描述，在报告里列出"需要在合并后复核的文档位置"清单。

## AC-1（P2）`.project_map` 必须重新生成

- AC-1.1 用 `scripts/map_project.py` 重新生成，使模块清单、依赖清单与实际代码一致。
- AC-1.2 生成后核对：`src/` 下每个 `.rs` 文件都出现在清单里；`Cargo.toml` 的依赖数量与清单一致。

## AC-2（P2）`CLAUDE.md` 的目录结构必须反映真实布局

- AC-2.1 补齐缺失模块（router、health、state_store、atomic_io、atomic_store、credential、
  active_home、launch_observation、repo_bundle、account/credential_store）。
- AC-2.2 补齐 `tests/`、`backlog/`、`.github/workflows/ci.yml`。
- AC-2.3 不要改动 CLAUDE.md 的角色定义、沟通协议和编码规范部分。

## AC-3（P2）`CLAUDE.md` 的测试指引必须包含凭据沙箱

- AC-3.1 测试与验证一节必须写明跑 `cargo test` / `cargo clippy` 前要设置
  `ANTIGRAVITY_CONFIG_DIR` 与 `GEMINI_HOME`，并说明原因（否则会覆盖开发机真实凭据）。

## AC-4（P2）`backlog/README.md` 记分板必须反映现状

- AC-4.1 更新发布状态段落：2026-08-24 报告里的 P0/P1 已基本关闭，
  引用新的 `reviews/2026-08-25-post-refactor-audit.md` 作为当前基线。
- AC-4.2 更新记分板：004a 与 013 已完成，不再是 FAIL。
- AC-4.3 待执行工单一节改为指向 `tasks-v3/`。
- AC-4.4 保留"执行者铁律"和"AC 设计规则"两节不动，它们仍然有效。

## AC-5（P3）安全逃生口必须被文档披露

- AC-5.1 `--insecure-host-key` 必须在两个 README 的同步章节里出现，
  说明它会关闭 SSH host key 校验、对应的 MITM 风险、以及默认是开启校验的。

## AC-6（P3）环境变量必须成文

- AC-6.1 在两个 README 里补一节，列出所有生效的环境变量
  （`SAGY_HOME`、`SAGY_POOL_REPO`、`SAGY_POOL_KEY`、`SAGY_UPDATE_REPO`、
  `ANTIGRAVITY_CONFIG_DIR`、`GEMINI_HOME`，以代码为准核对是否还有遗漏）。
- AC-6.2 说明 repo 来源的解析优先级（命令行参数、环境变量、`repo-sync.json` 三者的先后）。

## AC-7（P3）README 与 ARCHITECTURE 内部自洽

- AC-7.1 两个 README 的命令表、参数必填性必须一致，且与 clap 定义一致。
- AC-7.2 `ARCHITECTURE.md` 的目录结构与模块职责必须反映真实布局。
- AC-7.3 已删除的模型别名（flash/pro/think）不得在任何文档里残留。

## 自检

- 通用门禁照跑（你没改代码，应当全绿）。
- 额外交付：一份"合并后需要复核的文档位置"清单，指明哪些描述依赖其它工单的最终行为。
