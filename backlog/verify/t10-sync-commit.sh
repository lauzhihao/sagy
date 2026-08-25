#!/usr/bin/env bash
# T10 验收: pull 的协同提交在"坏账号"场景下不得硬失败 (R10-1 / R10-2)
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== T10 验收: pull 协同提交 =="
build_release
sbx_init

export SAGY_POOL_KEY="verify-only-passphrase-not-a-real-secret"
BARE="$SBX/pool.git"; git init --bare --quiet "$BARE"

machine() {
  local m="$1"; shift
  HOME="$SBX/home" SAGY_HOME="$SBX/m-$m/.sagy" \
  ANTIGRAVITY_CONFIG_DIR="$SBX/m-$m/agcli" GEMINI_HOME="$SBX/m-$m/gemini" \
  SAGY_POOL_KEY="$SAGY_POOL_KEY" PATH="$SBX/bin:$PATH" \
  "$REPO_ROOT/target/release/sagy" "$@"
}
mk_jwt() {
  local hdr='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
  local body; body="$(printf '{"exp":4102444800,"email":"%s"}' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  printf '%s.%s.sig' "$hdr" "$body"
}
for m in a b c; do mkdir -p "$SBX/m-$m/agcli" "$SBX/m-$m/gemini"; done

# alice: 建 doomed + keeper 两个账号并 push
machine a login --token "$(mk_jwt keeper@example.com)" --email keeper@example.com >/dev/null 2>&1
machine a login --token "$(mk_jwt doomed@example.com)" --email doomed@example.com >/dev/null 2>&1
machine a push "$BARE" >/dev/null 2>&1

# bob: pull 拿到两个账号
machine b pull "$BARE" >/dev/null 2>&1
OUT="$(machine b list 2>&1)"
assert_contains "$OUT" "doomed@example.com" "前置: bob 拿到了 doomed 账号"

# 让 doomed 成为 bob 的 current account, 并手工删掉它的凭据文件(模拟"凭据泄露后先删了文件")
machine b use doomed@example.com >/dev/null 2>&1
DOOMED_DIR="$(grep -rl "" "$SBX/m-b/.sagy/accounts" 2>/dev/null | head -1)"
DOOMED_ID="$(machine b list 2>&1 | grep doomed | awk '{print $1}')"
for d in "$SBX/m-b/.sagy/accounts"/*/; do
  if grep -rqs "" "$d" && [ -n "$(ls -A "$d" 2>/dev/null)" ]; then :; fi
done
# 直接按 state.json 里 doomed 的 id 定位目录
DID="$(python3 - "$SBX/m-b/.sagy/state.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))
for a in s.get("accounts",[]):
    if a.get("email")=="doomed@example.com": print(a["id"]); break
PY
)"
if [ -n "$DID" ] && [ -d "$SBX/m-b/.sagy/accounts/$DID" ]; then
  rm -f "$SBX/m-b/.sagy/accounts/$DID"/*
  _ok "前置: 已删除 doomed 在 bob 上的凭据文件"
else
  _bad "前置: 定位 doomed 的账号目录" "id=$DID"
fi

# alice: 同一次会话里新增 X 并删除 doomed, 然后 push
machine a login --token "$(mk_jwt newbie@example.com)" --email newbie@example.com >/dev/null 2>&1
machine a rm doomed@example.com -y >/dev/null 2>&1
machine a push "$BARE" >/dev/null 2>&1

# ---- R10-1.1 + R10-2.1: bob pull 必须成功 ----
OUT="$(machine b pull "$BARE" 2>&1)"; RC=$?
assert_eq "0" "$RC" "R10-1.1/2.1 混合场景(既有 import 又有坏账号删除, 且坏账号是 current)下 pull 成功"
[ "$RC" != "0" ] && printf '         pull stderr: %s\n' "$OUT"
assert_not_contains "$OUT" "does not cover every credential reference change" "R10-1.1 不再撞 proof 覆盖率校验"
assert_not_contains "$OUT" "coordinated commit requires" "R10-1.1 不再撞 coordinated commit proof 校验"

OUT="$(machine b list 2>&1)"; RC=$?
assert_eq "0" "$RC" "R10-2.1 pull 之后 bob 的 list 仍可用"
assert_not_contains "$OUT" "doomed@example.com" "R10-2.1 被删账号已从 bob 移除"
assert_contains "$OUT" "newbie@example.com" "R10-1.1 同一次 pull 里的新账号已导入"

report
