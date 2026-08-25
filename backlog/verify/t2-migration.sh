#!/usr/bin/env bash
# T2 验收: v1 迁移必须能跳过坏账号 (MIG-001)
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== T2 验收: v1 迁移逃生阀 =="
build_release
sbx_init

SAGY_ROOT="$SBX/home/.sagy"
seed_v1_state() {
  rm -rf "$SAGY_ROOT"
  mkdir -p "$SAGY_ROOT/accounts/good-1"
  printf '%s' "$FRESH_JWT" > "$SAGY_ROOT/accounts/good-1/antigravity-oauth-token"
  chmod 0600 "$SAGY_ROOT/accounts/good-1/antigravity-oauth-token"
  chmod 0700 "$SAGY_ROOT/accounts" "$SAGY_ROOT/accounts/good-1"
  cat > "$SAGY_ROOT/state.json" <<JSON
{
  "version": 1,
  "accounts": [
    {
      "id": "good-1",
      "email": "good@example.com",
      "account_type": "oauth",
      "auth_path": "$SAGY_ROOT/accounts/good-1/antigravity-oauth-token",
      "oauth_token": "$FRESH_JWT",
      "added_at": 1700000000,
      "updated_at": 1700000000
    },
    {
      "id": "broken-1",
      "email": "broken@example.com",
      "account_type": "oauth",
      "auth_path": "",
      "oauth_token": "",
      "added_at": 1700000000,
      "updated_at": 1700000000
    }
  ],
  "usage_cache": {},
  "current_account_id": null
}
JSON
  chmod 0600 "$SAGY_ROOT/state.json"
  chmod 0700 "$SAGY_ROOT"
}

# ---- AC-1.1 坏账号不得阻断整个 CLI ----
seed_v1_state
OUT="$(sagy_run list 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.1 含不可迁移账号时 sagy list 成功"
assert_contains "$OUT" "good@example.com" "AC-1.1 正常账号仍被列出"

# ---- AC-1.3 被跳过的账号必须对用户可见 ----
case "$OUT" in
  *broken*|*skip*|*Skip*|*SKIP*) _ok "AC-1.3 输出中提到了被跳过的账号" ;;
  *) _bad "AC-1.3 输出中提到了被跳过的账号" "$OUT" ;;
esac

# ---- AC-1.2 用户必须能用 CLI 管理账号 ----
seed_v1_state
OUT="$(sagy_run rm good@example.com -y 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.2 含坏账号时仍能执行 sagy rm"

# ---- AC-1.4 被跳过账号的原始数据不得被销毁 ----
seed_v1_state
cp "$SAGY_ROOT/state.json" "$SBX/state-before.json"
sagy_run list >/dev/null 2>&1
if grep -q "broken@example.com" "$SBX/state-before.json"; then
  FOUND=0
  grep -rq "broken@example.com" "$SAGY_ROOT" 2>/dev/null && FOUND=1
  [ "$FOUND" = "1" ] && _ok "AC-1.4 被跳过账号的数据仍保留在 state 目录中" \
    || _bad "AC-1.4 被跳过账号的数据仍保留在 state 目录中" "broken@example.com 已从磁盘消失"
fi

# ---- AC-1.5 全部账号不可迁移时仍须 exit 0 ----
rm -rf "$SAGY_ROOT"; mkdir -p "$SAGY_ROOT"
cat > "$SAGY_ROOT/state.json" <<JSON
{
  "version": 1,
  "accounts": [
    { "id": "broken-1", "email": "b1@example.com", "account_type": "oauth",
      "auth_path": "", "oauth_token": "", "added_at": 1, "updated_at": 1 },
    { "id": "broken-2", "email": "b2@example.com", "account_type": "oauth",
      "auth_path": "", "oauth_token": "", "added_at": 1, "updated_at": 1 }
  ],
  "usage_cache": {},
  "current_account_id": null
}
JSON
chmod 0600 "$SAGY_ROOT/state.json"; chmod 0700 "$SAGY_ROOT"
OUT="$(sagy_run list 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.5 全部账号不可迁移时 sagy list 仍 exit 0"

report
