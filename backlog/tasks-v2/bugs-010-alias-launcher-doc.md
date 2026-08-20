# bugs-010 别名路由问题：已由 bugs-013 取代

操作者决定不按模型分入口，三个别名二进制整体删除。
「alias 是否应该分流 sagy 子命令」这个问题随之消失。

本条关闭，改动并入 `bugs-013-drop-model-aliases.md`。

原工单遗留的一个独立议题**未随之解决**，需要时另开：

- `sagy`（裸跑）会注入 `--continue`，`sagy <prompt>` 不会。
  前者走 launch 分支 `resume=true`，后者走 passthrough 分支
  （`src/adapters/antigravity/launcher.rs` 的 `run_passthrough` 硬编码 `resume=false`）。
  带 prompt 时是否也应该续接上一轮会话，是一个产品决策，尚未拍板。
