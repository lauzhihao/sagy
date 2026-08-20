#!/usr/bin/env bash
# AC: 探测结果在 TTL 内复用; sagy refresh 强制刷新
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== bugs-006 验收: 探测 TTL 缓存 =="
build_release
sbx_init

sagy_run login --token "$FRESH_JWT" --email ttl@example.com >/dev/null 2>&1
T1="$(grep -o '"last_synced_at": [0-9]*' "$(state_json)" | head -1)"
sleep 2
sagy_run --no-launch >/dev/null 2>&1
T2="$(grep -o '"last_synced_at": [0-9]*' "$(state_json)" | head -1)"
assert_eq "$T1" "$T2" "TTL 内的第二次启动复用缓存, 不重新探测"

sleep 1
sagy_run refresh >/dev/null 2>&1
T3="$(grep -o '"last_synced_at": [0-9]*' "$(state_json)" | head -1)"
if [ "$T2" != "$T3" ]; then
  _ok "sagy refresh 强制刷新, 绕过 TTL"
else
  _bad "sagy refresh 强制刷新, 绕过 TTL" "last_synced_at 未变化: $T2"
fi

report
