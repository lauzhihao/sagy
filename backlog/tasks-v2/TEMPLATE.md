# bugs-NNN <一句话标题>

> 本文件是给执行者看的工单。执行者不需要做任何设计判断，
> 只需要按「改动」小节动手，然后跑「自检」小节的那一条命令。

## 目标

<一句话。说清楚改完之后系统的行为应该变成什么样，不描述实现。>

## 改动

逐条给出。每条必须指明文件、位置、改成什么。不给选项，不给"或者"。

1. `src/xxx.rs` 的 `fn yyy`（约第 NN 行）
   把
   ```rust
   <改动前的确切代码>
   ```
   改成
   ```rust
   <改动后的确切代码>
   ```

2. ...

## 禁止

- 不要修改 `backlog/verify/` 下的任何文件。验收脚本是只读的。
- 不要新增或修改 `#[cfg(test)]` 单元测试来让自检变绿。
- 不要改动本工单未列出的文件。
- 不要为了让检查通过而只添加字面字符串（例如只写一句注释里含关键词）。

## 自检

```bash
bash backlog/verify/bugs-NNN.sh
```

看到 `RESULT: PASS` 即为完成。看到 `RESULT: FAIL` 时，读 `[FAIL]` 那几行，
它会直接告诉你哪一条不满足、实际值是什么。改代码后重跑同一条命令。

## 完成信号

以下四条全部为 PASS 才算完成：

```bash
bash backlog/verify/bugs-NNN.sh
cargo fmt --check
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo clippy --all-targets -- -D warnings
ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary GEMINI_HOME=/tmp/sagy-canary cargo test
```

（cargo test / clippy 前面那两个环境变量是必须的，用来避免测试污染真实凭据目录。）

## 卡住时

连续 3 轮自检仍为 FAIL 就停下，不要继续猜。把最后一次的完整输出
和你改过的 diff 报告出来。不要为了让脚本变绿而绕过检查本身。
