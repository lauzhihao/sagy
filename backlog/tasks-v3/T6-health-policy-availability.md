# T6 健康状态机与可用性（P1）

先读 `backlog/tasks-v3/COMMON.md`。
背景见审计报告的 AVAIL-001、HTTP-400，以及 P3 的永久 cooldown、eligibility 两套定义、死代码。

## 归属文件（只能改这些）

- `src/core/policy.rs`
- `src/core/health.rs`
- `src/core/state.rs`
- `src/core/ui.rs`
- `src/adapters/antigravity/usage.rs`
- `src/adapters/antigravity/ui.rs`
- 新建：`tests/p1_offline_availability.rs`

不要改 `src/cli/mod.rs`（属于 T7）。所有修复都必须能在你的归属文件里表达。

## AC-1（P1）探测通道故障不得让 sagy 拒绝启动

现状：probe 的 timeout/network 失败 -> `TransientFailure` -> `Ineligible`，
断网/代理/域名不可达时全部账号被判不可用，`sagy launch` 打印"无可用账号"并 exit 1，
agy 根本没有被 spawn——即使凭据完全有效。

- AC-1.1 所有账号的最近一次探测都是传输层失败（timeout / DNS / 连接被拒）时，
  本地凭据校验通过的账号必须仍可被选中启动。
- AC-1.2 该场景下的账号选择顺序必须是确定的、可测试的（说明你的排序规则）。
- AC-1.3 传输失败与"服务端明确拒绝"（401/403/无效凭据）必须区别对待：
  后者仍然不可选。断网不能让一个已知失效的凭据变得可选。
- AC-1.4 该场景下给用户的提示不得再是"去 `sagy add` 添加账号"，
  必须说明真实原因是探测通道不可达，并说明 sagy 仍在用缓存/本地校验结果继续。
- AC-1.5 回归测试必须在**无网络**条件下可判定（把探测端点指向不可路由地址或用注入点，
  不得依赖真实网络）。

## AC-2（P2）HTTP 400 必须进入状态矩阵

- AC-2.1 API key 探测收到 400 时，账号状态必须迁移到"凭据无效/需要重新登录"这一类，
  而不是传输故障类。
- AC-2.2 `sagy list` 对该账号必须显示需要用户处理的状态，而不是显示成暂时性故障。
- AC-2.3 状态矩阵测试必须显式覆盖 200 / 400 / 401 / 403 / 429 / 500 / timeout / network 全部分支。

## AC-3（P3）cooldown 不得因时钟跳变变成永久

- AC-3.1 state 中存在 `started_at` 在未来的 cooldown 记录时，该记录必须被视为无效并清除，
  账号必须能重新被探测和选中。
- AC-3.2 `sagy refresh` 的强制刷新语义必须能穿透这种无效 cooldown。
- AC-3.3 正常的、未过期的 cooldown 不得被本改动误清除。

## AC-4（P3）可选性判定只能有一处定义

- AC-4.1 全库不得存在第二套与 `policy::eligibility` 语义不同的账号可选性判定。
- AC-4.2 探测 TTL 常量只能有一份定义。
- AC-4.3 已无生产调用方的 `pub` 项（限流标记、健康判定等）必须删除；
  删除时同步更新引用它们的既有测试。

## 自检

除通用门禁外，AC-1.1 必须给出黑盒复现：隔离 HOME + 有效凭据 + 探测端点不可达 -> `sagy launch` 必须
真的把 agy 拉起来（用 fake agy 记录 argv 证明）。
