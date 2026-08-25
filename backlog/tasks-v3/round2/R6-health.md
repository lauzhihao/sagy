# R6 健康状态机复核回归

先读 `backlog/tasks-v3/round2/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round2/R6`

## 归属文件

- `src/core/policy.rs`
- `src/core/health.rs`
- `src/adapters/antigravity/usage.rs`
- `src/core/ui.rs`
- `src/adapters/antigravity/ui.rs`
- `tests/p1_offline_availability.rs`

## R6-1（重要）断网兜底只认 Timeout/Network，代理故障不生效

离线兜底只覆盖 `ProbeOutcome::Timeout` 与 `Network`。而现实中出网失败经常表现为
代理返回 407 / 302 / 404 / 502，这些落进 `OtherTransient` -> `ServerFailure`，
兜底不生效，sagy 仍然拒绝启动——AVAIL-001 在最常见的"公司代理"场景下没有真正修好。

- AC-R6-1.1 探测收到 407、302、404、502、503 时，本地凭据校验通过的账号仍必须可被选中启动。
- AC-R6-1.2 服务端明确拒绝凭据的状态码（400/401/403）仍然不可选，不得被本改动放宽。
- AC-R6-1.3 测试用注入的 HTTP 状态覆盖上述全部状态码，断言可选性结论。

## R6-2 探测退避窗被拉长

传输失败保留服务端拒绝结论时会顺带刷新 `last_probe_at`，
使下一次重探从 30 秒退避窗变成 300 秒 TTL 窗。

- AC-R6-2.1 传输失败不得延长下一次重探的等待时间。
- AC-R6-2.2 测试断言两种失败下的下一次重探时机。

## R6-3 400 -> Relogin Required 缺端到端链路

现有用例直接注入 `invalid_credential` 健康态，断言在改动前也是绿的。

- AC-R6-3.1 从"探测返回 400"出发，断言 `sagy list` 的状态列显示需要重新登录。
- AC-R6-3.2 反向验证：把 400 的分类改回 OtherTransient，该测试必须变红。

## R6-4 守门测试的断言方式

`PROBE_TTL` 的守门用例用裸子串断言 usage.rs 不含该字符串，
会连合法的 `use crate::core::health::PROBE_TTL_SECS` 一起误杀。

- AC-R6-4.1 改成只禁止**重新定义**常量，允许引用。

## R6-5 cooldown 显示不一致

账号表格的 Cooldown 分支读的是未归一化的 `cooldown_until()`，
与 `is_in_cooldown()` / `eligibility` 的归一化语义不一致（当前经由 CLI 不可达）。

- AC-R6-5.1 统一到归一化语义。
