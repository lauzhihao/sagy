#!/usr/bin/env bash
# T11 验收: 已有 Antigravity 凭据的机器上, 首次使用 sagy 不得被 active-home 卡死
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== T11 验收: 首次接管既有 Antigravity 凭据 =="
build_release
sbx_init

# 探测端点不可达: 让健康判定走离线兜底, 使 launch 路径在沙箱中可判定
offline_run() {
  HTTPS_PROXY="http://127.0.0.1:1" HTTP_PROXY="http://127.0.0.1:1" ALL_PROXY="http://127.0.0.1:1" \
  https_proxy="http://127.0.0.1:1" http_proxy="http://127.0.0.1:1" all_proxy="http://127.0.0.1:1" \
  sagy_run "$@"
}

# --- 场景 1: 机器上本来就在用 Antigravity(sagy 之前没碰过它) ---
printf '%s' "$FRESH_JWT" > "$SBX/agcli/antigravity-oauth-token"
OUT="$(offline_run import-known 2>&1)"; RC=$?
assert_eq "0" "$RC" "场景1: import-known 成功"
assert_contains "$OUT" "Imported account" "场景1: 既有凭据被导入"

: > "$FAKE_AGY_LOG"
OUT="$(offline_run launch 2>&1)"; RC=$?
assert_eq "0" "$RC" "场景1: 导入后 sagy launch 成功"
assert_not_contains "$OUT" "adopt/takeover" "场景1: 不报 active-home 需要 adopt/takeover"
if [ -n "$(agy_argv)" ]; then _ok "场景1: agy 子进程被启动"
else _bad "场景1: agy 子进程被启动" "fake agy 从未被调用; 输出: $OUT"; fi

# --- 场景 2: 用户删掉 ~/.sagy 重来(state 没了, ~/.gemini 里还留着 sagy 写的凭据) ---
rm -rf "$SBX/home/.sagy"
OUT="$(offline_run login --token "$FRESH_JWT" --email again@example.com 2>&1)"; RC=$?
assert_eq "0" "$RC" "场景2: 删掉 state 后重新 login 成功"
assert_not_contains "$OUT" "adopt/takeover" "场景2: login 不报 adopt/takeover"

: > "$FAKE_AGY_LOG"
OUT="$(offline_run launch 2>&1)"; RC=$?
assert_eq "0" "$RC" "场景2: 重新 login 后 launch 成功"
if [ -n "$(agy_argv)" ]; then _ok "场景2: agy 子进程被启动"
else _bad "场景2: agy 子进程被启动" "fake agy 从未被调用; 输出: $OUT"; fi

# --- 场景 3: active home 里是 sagy 不认识的凭据 -> 不得静默覆盖, 但必须给出可执行的下一步 ---
rm -rf "$SBX/home/.sagy"
printf 'a-foreign-credential-not-managed-by-sagy' > "$SBX/agcli/antigravity-oauth-token"
offline_run login --token "$FRESH_JWT" --email owner@example.com >/dev/null 2>&1
OUT="$(offline_run launch 2>&1)"; RC=$?
if [ "$RC" = "0" ]; then
  _ok "场景3: 陌生凭据下 launch 未被卡死"
else
  case "$OUT" in
    *sagy*--*) _ok "场景3: 被拒绝时给出了可执行的 sagy 命令" ;;
    *) _bad "场景3: 被拒绝时给出了可执行的 sagy 命令" "$OUT" ;;
  esac
fi

report
