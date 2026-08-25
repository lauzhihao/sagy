# R8 文档复核回归

先读 `backlog/tasks-v3/round2/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round2/R8`

## 归属文件

- `README.md`
- `README.zh-CN.md`
- `ARCHITECTURE.md`
- `CLAUDE.md`
- `AGENTS.md`
- `.project_map`

不要改 `backlog/` 下任何文件（验收方自己维护），也不要改 `src/` 与 `tests/`。

## R8-1（MAJOR）README 谎称 `sagy login` 是交互式 OAuth 流程

第一轮的 diff 新引入了这个错误事实。代码实际只是用 rpassword 隐藏输入让用户粘贴一个**已有的** token，
没有任何 OAuth 授权流程（不开浏览器、不换 code、不请求 refresh token）。

- AC-R8-1.1 两个 README 对 `sagy login` 的描述必须与实现一致。
- AC-R8-1.2 顺带核对：仓库里是否存在任何 refresh token 换取 access token 的实现？
  以代码为准写，不要照抄旧描述。

## R8-2 参数描述与实现不符

- AC-R8-2.1 `--api` 在代码里是无效开关（给了 `--api-key` 它不参与判断，
  不给 `--api-key` 它只能产出一条报错）。据实描述或建议删除（删除属 CLI 归属，你只提出）。
- AC-R8-2.2 参数表补齐 `--oauth` 与 `--no-resume`。
- AC-R8-2.3 `--all` 已被删除，确认文档里没有残留。

## R8-3 resume 规则必须成文

第一轮 T7 定下的规则是：
(1) 默认续接上一轮会话，只有显式 `--no-resume` 关闭；
(2) 当传给 agy 的参数本身已承载会话意图时不叠加（出现 `--prompt`/`-p`/`--print`/`-c`/
`--continue`/`--conversation`/裸 positional/`--` 边界之一时，交给 agy 决定）。

- AC-R8-3.1 在 ARCHITECTURE.md 写明这两条，并在两个 README 的命令表里体现。
- AC-R8-3.2 以当前代码复核这两条描述是否属实，不符就以代码为准并在报告里指出。

## R8-4 模块职责描述错误

CLAUDE.md 与 ARCHITECTURE.md 给 `auth.rs` 写的职责是 "Credential parsing, token refresh"，
但该文件里没有任何 token refresh。

- AC-R8-4.1 按真实代码重写每个模块一行职责，逐个文件核对，不要照抄。

## R8-5 环境变量与 project map

- AC-R8-5.1 环境变量一节补上 launcher 会主动清掉的父进程变量（以代码里的 deny-list 为准）。
- AC-R8-5.2 重新生成 `.project_map`（用 `scripts/map_project.py`），
  确保不包含任何本地编译产物计数，且包含 `backlog/tasks-v3/` 与新的审计报告。
