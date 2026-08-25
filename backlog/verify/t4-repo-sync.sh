#!/usr/bin/env bash
# T4 验收: 账号池同步的数据安全 (SYNC-101 divergence / pool_id 规范化 / 删除传播)
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== T4 验收: 账号池同步 =="
build_release
sbx_init

export SAGY_POOL_KEY="verify-only-passphrase-not-a-real-secret"
BARE="$SBX/pool.git"
git init --bare --quiet "$BARE"
# 本地裸仓库用普通路径引用: file:// 形式因缺少 host 被信任边界拒绝
REPO_URL="$BARE"

# 每台"机器"一个独立 state dir
machine() {
  local m="$1"; shift
  HOME="$SBX/home" \
  SAGY_HOME="$SBX/m-$m/.sagy" \
  ANTIGRAVITY_CONFIG_DIR="$SBX/m-$m/agcli" \
  GEMINI_HOME="$SBX/m-$m/gemini" \
  SAGY_POOL_KEY="$SAGY_POOL_KEY" \
  PATH="$SBX/bin:$PATH" \
  "$REPO_ROOT/target/release/sagy" "$@"
}
mk_jwt() { # 生成一个 exp=2100 的、email 不同的假 JWT (仅用于本地校验, 非真实凭据)
  local email="$1"
  local hdr='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
  local body; body="$(printf '{"exp":4102444800,"email":"%s"}' "$email" \
    | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  printf '%s.%s.sig' "$hdr" "$body"
}

for m in a b c; do mkdir -p "$SBX/m-$m/agcli" "$SBX/m-$m/gemini"; done

# A: 建号并首次 push
machine a login --token "$(mk_jwt a@example.com)" --email a@example.com >/dev/null 2>&1
OUT="$(machine a push "$REPO_URL" 2>&1)"; RC=$?
assert_eq "0" "$RC" "前置: A 首次 push 成功"

# B: pull 后新增账号并 push (远端 generation 前进)
OUT="$(machine b pull "$REPO_URL" 2>&1)"; RC=$?
assert_eq "0" "$RC" "前置: B pull 成功"
machine b login --token "$(mk_jwt b@example.com)" --email b@example.com >/dev/null 2>&1
OUT="$(machine b push "$REPO_URL" 2>&1)"; RC=$?
assert_eq "0" "$RC" "前置: B push 成功"

# ---- AC-1.1 A 未 pull 就 push 必须被拒绝 ----
machine a login --token "$(mk_jwt a2@example.com)" --email a2@example.com >/dev/null 2>&1
OUT="$(machine a push "$REPO_URL" 2>&1)"; RC=$?
if [ "$RC" != "0" ]; then
  _ok "AC-1.1 落后于远端时 push 被拒绝"
  case "$OUT" in *pull*|*behind*|*落后*) _ok "AC-1.1 错误信息提示先 pull" ;;
    *) _bad "AC-1.1 错误信息提示先 pull" "$OUT" ;; esac
else
  _bad "AC-1.1 落后于远端时 push 被拒绝" "rc=0, 远端已被覆盖"
fi

# ---- AC-1.4 B 的账号不得从池中消失 ----
OUT="$(machine c pull "$REPO_URL" 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.4 全新机器 C pull 成功"
OUT="$(machine c list 2>&1)"
assert_contains "$OUT" "b@example.com" "AC-1.4 B 新增的账号仍在池中"
assert_contains "$OUT" "a@example.com" "AC-1.4 A 最初的账号仍在池中"

# ---- AC-1.2 先 pull 再 push 必须成功且合并双方账号 ----
OUT="$(machine a pull "$REPO_URL" 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.2 A pull 成功"
OUT="$(machine a push "$REPO_URL" 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.2 A pull 后 push 成功"
rm -rf "$SBX/m-c"; mkdir -p "$SBX/m-c/agcli" "$SBX/m-c/gemini"
machine c pull "$REPO_URL" >/dev/null 2>&1
OUT="$(machine c list 2>&1)"
assert_contains "$OUT" "a2@example.com" "AC-1.2 A 新增的账号已进入池"
assert_contains "$OUT" "b@example.com" "AC-1.2 B 的账号未被覆盖"

# ---- AC-4.1 同一仓库的不同 URL 写法必须是同一个池 ----
OUT="$(machine a pull "$BARE/" 2>&1)"; RC=$?
if [ "$RC" = "0" ]; then _ok "AC-4.1 带尾部斜杠的同一仓库视为同一个池"
else
  _bad "AC-4.1 带尾部斜杠的同一仓库视为同一个池" "$OUT"
fi

# ---- AC-3.1 删除必须能传播 ----
machine a rm a2@example.com -y >/dev/null 2>&1
machine a push "$REPO_URL" >/dev/null 2>&1
rm -rf "$SBX/m-c"; mkdir -p "$SBX/m-c/agcli" "$SBX/m-c/gemini"
machine c pull "$REPO_URL" >/dev/null 2>&1
OUT="$(machine c list 2>&1)"
assert_not_contains "$OUT" "a2@example.com" "AC-3.1 已删除的账号不会在新机器上复活"

report
