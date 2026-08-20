# bugs-003 flash/pro/think 注入的 model ID 在 agy 中不存在

- 严重度: P0 (三个卖点入口全部失效)
- 状态: 待修复
- 引入版本: 99421bb (初始实现，两轮修复均未触及)
- 影响面: `flash` / `pro` / `think` 全部三个快捷入口

## 现象

`src/adapters/antigravity/launcher.rs:43-70` 注入的 model ID 与 agy 实际接受的
标识不匹配：

| 入口 | 当前注入 | agy 实际存在的 ID |
| :--- | :--- | :--- |
| flash | `--model gemini-3.7-flash --effort low` | `gemini-3.7-flash-low` |
| think | `--model gemini-3.7-flash --effort high` | `gemini-3.7-flash-high` |
| pro | `--model gemini-3.7-pro --effort high` | 无此模型，最接近的是 `gemini-3.1-pro-high` |

## 证据

本机 `agy models` 输出（权威来源）:

```text
gemini-3.7-flash-high    Gemini 3.7 Flash (High)
gemini-3.7-flash-medium  Gemini 3.7 Flash (Medium)
gemini-3.7-flash-low     Gemini 3.7 Flash (Low)
gemini-3.6-flash-high    ...
gemini-3.1-pro-high      Gemini 3.1 Pro (High)
gemini-3.1-pro-low       Gemini 3.1 Pro (Low)
claude-sonnet-4-6        Claude Sonnet 4.6 (Thinking)
claude-opus-4-6-thinking Claude Opus 4.6 (Thinking)
gpt-oss-120b-medium      GPT-OSS 120B (Medium)
```

effort 是烧进 model ID 的；`--effort low|medium|high` 是另一个独立参数
（`agy --help` 确认存在）。不存在 `gemini-3.7-flash` 这个裸 ID，
也完全不存在任何 `gemini-3.7-pro`。

操作者自己的 shell alias 用的是 `--model "Gemini 3.7 Flash (High)"`，
即显示名而非 slug，进一步说明裸 ID 不是有效输入。

## 待确认

尚未实测 agy 对无效 model ID 的具体反应（会报错拒绝，还是回退默认模型）。
未实测的原因：实测需要消耗真实 token 额度，且当前本机 token 文件已被
bugs-001 破坏。修复时应顺带确认，以判断这是"硬失败"还是"静默降级"。

## 修复方案

1. 将三个入口的注入值改为：
   - `flash` -> `--model gemini-3.7-flash-low`
   - `think` -> `--model gemini-3.7-flash-high`
   - `pro`   -> `--model gemini-3.1-pro-high`
2. 去掉随附的 `--effort` 注入（已包含在 ID 内），或保留但确认二者不冲突。
3. 把这三个值提取为模块级常量并加注释，说明来源是 `agy models`，
   避免下次 agy 升级后再次漂移。
4. 同步更新 `README.md`、`README.zh-CN.md`、`src/cli/help.rs` 里的模型说明表。

## 验收标准

- [ ] `flash` / `pro` / `think` 各跑一次，实际传给 agy 的 argv 与 `agy models` 中
      的 ID 完全一致（用假 agy 脚本打印 argv 验证）
- [ ] 用真实 agy 各跑一次最短交互，确认模型被正确接受
- [ ] 三份文档中的模型表与代码一致
