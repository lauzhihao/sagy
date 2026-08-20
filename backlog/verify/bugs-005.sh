#!/usr/bin/env bash
# AC: 删除不可达的 code==429 判断, 改为子进程失败后立即重新探测该账号
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== bugs-005 验收: 限流检测路径可达 =="
build_release
sbx_init

# 1. 源码中不得再出现基于退出码的 429 判断 (Unix 退出码只有 8 bit, 永远不成立)
assert_grep_absent 'code *== *429' "$REPO_ROOT/src" "源码中不再有 code == 429 死条件"

# 2. 子进程非 0 退出后, 该账号的 last_synced_at 必须被刷新
sagy_run login --token "$FRESH_JWT" --email rl@example.com >/dev/null 2>&1
BEFORE="$(grep -o '"last_synced_at": [0-9]*' "$(state_json)" | head -1)"
sleep 1
FAKE_AGY_EXIT=1 sagy_run >/dev/null 2>&1
AFTER="$(grep -o '"last_synced_at": [0-9]*' "$(state_json)" | head -1)"
if [ "$BEFORE" != "$AFTER" ]; then
  _ok "子进程失败后触发了该账号的重新探测"
else
  _bad "子进程失败后触发了该账号的重新探测" "last_synced_at 未变化: $BEFORE"
fi

# 3. 子进程成功退出时不应额外探测(避免每次都多打一次网络)
BEFORE2="$(grep -o '"last_synced_at": [0-9]*' "$(state_json)" | head -1)"
sleep 1
FAKE_AGY_EXIT=0 sagy_run >/dev/null 2>&1
AFTER2="$(grep -o '"last_synced_at": [0-9]*' "$(state_json)" | head -1)"
assert_eq "$BEFORE2" "$AFTER2" "子进程成功退出时不额外探测"

report
