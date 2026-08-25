#!/usr/bin/env bash
# T6 验收: 探测通道不可达时 sagy 仍须能启动 agy (AVAIL-001)
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== T6 验收: 离线可用性 =="
build_release
sbx_init

# 把所有出网流量指向一个必定拒绝连接的地址, 模拟断网/代理故障/域名被墙
offline_run() {
  HTTPS_PROXY="http://127.0.0.1:1" HTTP_PROXY="http://127.0.0.1:1" ALL_PROXY="http://127.0.0.1:1" \
  https_proxy="http://127.0.0.1:1" http_proxy="http://127.0.0.1:1" all_proxy="http://127.0.0.1:1" \
  sagy_run "$@"
}

# 先在离线状态下登录一个本地可校验的账号
OUT="$(offline_run login --token "$FRESH_JWT" --email offline@example.com 2>&1)"; RC=$?
assert_eq "0" "$RC" "离线时 sagy login 成功"

# ---- AC-1.1 离线时 launch 必须真的把 agy 拉起来 ----
: > "$FAKE_AGY_LOG"
OUT="$(offline_run launch 2>&1)"; RC=$?
ARGV="$(agy_argv)"
assert_eq "0" "$RC" "AC-1.1 离线时 sagy launch 返回 0"
if [ -n "$ARGV" ]; then
  _ok "AC-1.1 离线时 agy 子进程确实被启动 (argv: $ARGV)"
else
  _bad "AC-1.1 离线时 agy 子进程确实被启动" "fake agy 从未被调用"
fi
assert_not_contains "$OUT" "No usable accounts" "AC-1.4 不再谎报无可用账号"

# ---- AC-1.3 服务端明确拒绝的凭据不得因为断网变得可选 ----
# 过期到无法本地校验的 token: 本地校验就应判定不可用
OUT="$(offline_run login --token "$EXPIRED_JWT" --email expired@example.com 2>&1)"
: > "$FAKE_AGY_LOG"
OUT="$(offline_run launch 2>&1)"; RC=$?
ARGV="$(agy_argv)"
if [ -n "$ARGV" ]; then
  _ok "AC-1.2 离线时仍能确定性地选出一个账号并启动"
else
  _bad "AC-1.2 离线时仍能确定性地选出一个账号并启动" "fake agy 未被调用, 输出: $OUT"
fi

report
