# R7 安装器与自更新复核回归

先读 `backlog/tasks-v3/round2/COMMON.md`。工作目录：`/private/tmp/claude-501/-Users-liuzhihao-Documents-sagy/5494f193-7fca-4d41-bb30-6f93a3d17659/scratchpad/round2/R7`

## 归属文件

- `src/core/update.rs`
- `install.sh`
- `install.ps1`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `tests/p0_checksum.rs`
- `tests/p0_checksum.ps1`
- `tests/ci_workflow.rs`

## R7-1（MAJOR）下载体积上限没有回归保护

`update.rs` 的体积上限只有内部 helper 的单元测试，三个真实调用点
（release metadata、checksum 清单、二进制本体）没有任何覆盖；把任意一处改回无界读取，测试仍全绿。

- AC-R7-1.1 三个调用点各有一个测试，喂超过上限的响应体，断言 fail-closed 且不落盘/不替换二进制。
- AC-R7-1.2 反向验证：把任一调用点的上限去掉，对应测试必须变红。

## R7-2（MAJOR）install.sh 的失败可见性没有 fail-before 覆盖

- AC-R7-2.1 用假下载源在本地跑 `install.sh`，构造安装后动作失败的场景，
  断言脚本打印了可见的失败提示且退出码非 0。
- AC-R7-2.2 反向验证：把提示改回 `>/dev/null 2>&1` 吞掉，该测试必须变红。

## R7-3（MAJOR）Windows 侧全部是代码级推断

本机没有 pwsh / powershell（已确认），`tests/p0_checksum.ps1` 被整体重写 272 行但从未执行过一次。

- AC-R7-3.1 不要假装能在本机验证。你要做的是让 **CI** 成为唯一且充分的证据：
  确认 ci.yml 的 Windows job 真的执行了这个脚本，且脚本的每一条 fail-closed 用例
  在失败时会让 job 变红（检查退出码传播、$ErrorActionPreference、$LASTEXITCODE 的处理）。
- AC-R7-3.2 在报告里明确写出："Windows 侧的证据等级 = CI 未运行前为零"，
  并列出 CI 第一次跑起来时最可能失败的三个点。
- AC-R7-3.3 `tests/p0_checksum.rs` 里被删掉的两条既有断言（install.ps1 的"空文件"守卫）
  必须以某种形式补回锚点。

## R7-4（MINOR）

- AC-R7-4.1 install.sh 新增的 INT/TERM trap 只清理不重抛，Ctrl-C 后脚本可能带着
  已删除的工作目录继续执行。改成清理后重抛信号。
- AC-R7-4.2 `both_installers_resolve_original_agy_in_the_same_order` 的 AGY_BIN/gemini 锚点
  落在注释行上，install.sh 的真实分支顺序怎么改都抓不到。改成断言真实分支。
- AC-R7-4.3 install.ps1 的体积上限是"整份落盘后再量"，与 install.sh 的传输中止、
  update.rs 的流式截断语义不一致。统一语义或在脚本注释里说明为什么不能统一。
