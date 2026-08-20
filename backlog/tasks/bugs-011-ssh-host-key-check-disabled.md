# bugs-011 repo sync 在指定 -i 时关闭 SSH host key 校验

- 严重度: P2 (安全)
- 状态: 待修复
- 引入版本: 99421bb (两轮修复均未触及)

## 现象

`src/adapters/antigravity/repo_sync.rs:379-386`:

```text
GIT_SSH_COMMAND=ssh -i <key> -o IdentitiesOnly=yes -o StrictHostKeyChecking=no
```

对一个专门用来同步账号凭据的仓库关闭 host key 校验，等于自愿接受中间人攻击：
攻击者可以冒充 git 服务器接收 push（拿到加密 bundle）或提供伪造的 bundle。

bundle 本身是 Argon2id + XChaCha20Poly1305 加密的，所以直接读取内容仍需口令，
但攻击者可以离线爆破弱口令、也可以做拒绝服务或投毒（提供旧版本 bundle 回滚账号池）。

## 修复方案

1. 去掉 `-o StrictHostKeyChecking=no`，默认走用户的 known_hosts。
2. 首次连接失败时给出明确提示，引导用户先手工 `ssh-keyscan` 或直接 `ssh -T`
   完成一次指纹确认，而不是替他关掉校验。
3. 若确实需要非交互场景的逃生口，改成显式 opt-in 的
   `--insecure-host-key` 参数，并在使用时打印醒目警告。
   默认必须是安全的。

## 验收标准

- [ ] 未指定逃生参数时，连接未知主机会因 host key 校验失败而中止
- [ ] 已在 known_hosts 中的主机可正常 push/pull
- [ ] 逃生参数（若实现）会打印警告
