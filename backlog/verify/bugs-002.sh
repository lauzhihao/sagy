#!/usr/bin/env bash
# AC: 过期但可续期的 token 不得被判死, sagy 必须能正常启动
# 注意: 本脚本只断言可观察行为, 不断言内部状态字符串的具体取值。
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== bugs-002 验收: 过期可续期 token 不阻塞启动 =="
build_release
sbx_init

# --- 场景 A: 过期 JWT + 有 refresh_token -> 必须可用 ---
cat > "$SBX/creds-a.json" <<JSONEOF
{"token":"$EXPIRED_JWT","refresh_token":"1//fake_refresh","email":"renewable@example.com"}
JSONEOF
sagy_run import-auth "$SBX/creds-a.json" >/dev/null 2>&1

OUT="$(sagy_run --no-launch 2>&1)"; CODE=$?
assert_eq "0" "$CODE" "场景A: 持有 refresh_token 的过期账号可启动 (exit 0)"
assert_not_contains "$OUT" "No usable accounts" "场景A: 不报告无可用账号"
assert_not_contains "$(cat "$(state_json)")" '"needs_relogin": true' \
  "场景A: 不置 needs_relogin"

# --- 场景 B: 过期 JWT + 无 refresh_token -> 必须判为需重登 ---
rm -rf "$SBX/home/.sagy"
sagy_run login --token "$EXPIRED_JWT" --email norenew@example.com >/dev/null 2>&1
sagy_run list >/dev/null 2>&1
assert_contains "$(cat "$(state_json)")" '"needs_relogin": true' \
  "场景B: 无续期材料时仍判为需重登(证明探测确实在跑)"

# --- 场景 C: 未过期 JWT -> 正常可用 ---
rm -rf "$SBX/home/.sagy"
sagy_run login --token "$FRESH_JWT" --email fresh@example.com >/dev/null 2>&1
OUT3="$(sagy_run --no-launch 2>&1)"; CODE3=$?
assert_eq "0" "$CODE3" "场景C: 未过期 token 可启动"
assert_not_contains "$(cat "$(state_json)")" '"needs_relogin": true' \
  "场景C: 未过期 token 不被判死"

report
