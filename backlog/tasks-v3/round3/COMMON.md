# tasks-v3 第三轮（收尾）通用规则

第一轮与第二轮的实现均已合并进主仓库，门禁全绿。第三轮处理第二轮复核仍然挂账的 major 与真实 minor。
第二轮处理的是独立复核者在第一轮 diff 里发现的 **blocker / major / 真实 minor**。

## 工作方式（与第一轮不同，务必照做）

1. 你**不在** git worktree 里。第一步必须把主仓库复制一份到你自己的目录：

```bash
DEST=<你的工单指定的目录>
mkdir -p "$DEST"
rsync -a --exclude 'target/' --exclude '.claude/' /Users/liuzhihao/Documents/sagy/ "$DEST"/
cd "$DEST"
```

之后**所有**读写都在 `$DEST` 里进行。主仓库 `/Users/liuzhihao/Documents/sagy` 对你**只读**，
一个字节都不要改——那是验收方的工作副本，你改了会破坏另外 8 个并行 agent。

2. 只允许修改工单"归属文件"列出的文件。验收方只会把这些文件从你的目录拷回主仓库，
   改其它文件等于白改。
3. 不新增第三方依赖。
4. 跑 cargo 前必须 `export ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary`。
5. 门禁必须全绿：`cargo fmt`、`cargo clippy --all-targets -- -D warnings`、`cargo test --all-targets`。
6. 控制台输出 ASCII only；注释用中文写"为什么"。

## 这一轮的核心要求：测试必须真的能抓住 bug

第一轮最普遍的问题是**测试打在新加的内部函数上，而不是 AC 描述的可观察行为**——
把修复代码撤掉，测试照样绿。这一轮每加一个测试，你必须自己做一次"反向验证"：

> 把你这次的修复代码临时改回有 bug 的样子，确认新测试**变红**，再改回来。

报告里必须写清你对哪几个测试做了这个反向验证、撤掉哪一行会让它红。
做不到反向验证的测试不要写，直接说明为什么该行为无法在测试里捕获。

## 最终报告

- 每条修复项的实现位置 file:line
- 每个新增/修改测试的名字 + 反向验证结果
- 你的工作目录绝对路径
- 没做完的项目及原因
