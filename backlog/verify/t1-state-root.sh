#!/usr/bin/env bash
# T1 验收: state root 可用性 (ROOT-001 / ROOT-002 / 权限迁移)
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== T1 验收: state root 可用性 =="
build_release
sbx_init

SAGY_ROOT="$SBX/home/.sagy"

# 在指定 cwd 下运行 sagy
sagy_run_in() {
  local dir="$1"; shift
  ( cd "$dir" && HOME="$SBX/home" SAGY_HOME="$SAGY_ROOT" \
    ANTIGRAVITY_CONFIG_DIR="$SBX/agcli" GEMINI_HOME="$SBX/gemini" \
    FAKE_AGY_LOG="$FAKE_AGY_LOG" PATH="$SBX/bin:$PATH" \
    "$REPO_ROOT/target/release/sagy" "$@" )
}

# ---- AC-1.1 安装器创建的 bin/ 不得让命令失败 ----
mkdir -p "$SAGY_ROOT/bin"
OUT="$(sagy_run list 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.1 root 下有 bin/ 时 sagy list 成功"
assert_not_contains "$OUT" "unknown state root entry" "AC-1.1 不报 unknown state root entry"

# ---- AC-1.2 全新 root 只有 tmp/ ----
rm -rf "$SAGY_ROOT"; mkdir -p "$SAGY_ROOT/tmp"
OUT="$(sagy_run list 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.2 全新 root 只有 tmp/ 时 sagy list 成功"
assert_not_contains "$OUT" "non-atomic entry" "AC-1.2 不报 state-less root contains non-atomic entry"

# ---- AC-1.2b 全新 root 上先写 repo-sync.json (sagy pull 的真实首步) ----
# 现实路径: 全新机器第一条命令是 `sagy pull <repo>`，它会在 state.json 之前落盘 repo-sync.json
rm -rf "$SAGY_ROOT"; mkdir -p "$SAGY_ROOT"
printf '{"last_repo":"/tmp/x.git"}' > "$SAGY_ROOT/repo-sync.json"
chmod 0600 "$SAGY_ROOT/repo-sync.json"
OUT="$(sagy_run list 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.2b 全新 root 只有 repo-sync.json 时 sagy list 成功"
assert_not_contains "$OUT" "non-atomic entry" "AC-1.2b 不报 state-less root contains non-atomic entry"

# ---- AC-1.3 / AC-1.4 陌生条目被忽略且不被改动 ----
rm -rf "$SAGY_ROOT"; mkdir -p "$SAGY_ROOT/bin" "$SAGY_ROOT/backup"
printf 'user notes\n' > "$SAGY_ROOT/notes.txt"
printf 'ds\n' > "$SAGY_ROOT/.DS_Store"
printf 'old\n' > "$SAGY_ROOT/backup/old.json"
SUM_BEFORE="$(cat "$SAGY_ROOT/notes.txt" "$SAGY_ROOT/.DS_Store" "$SAGY_ROOT/backup/old.json" | shasum -a 256 | cut -d' ' -f1)"
OUT="$(sagy_run list 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.3 root 下有陌生条目时 sagy list 成功"
OUT="$(sagy_run login --token "$FRESH_JWT" --email t1@example.com 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-1.3 写 state 的命令在有陌生条目时也成功"
SUM_AFTER="$(cat "$SAGY_ROOT/notes.txt" "$SAGY_ROOT/.DS_Store" "$SAGY_ROOT/backup/old.json" | shasum -a 256 | cut -d' ' -f1)"
assert_eq "$SUM_BEFORE" "$SUM_AFTER" "AC-1.4 陌生条目内容未被改动"
[ -f "$SAGY_ROOT/notes.txt" ] && _ok "AC-1.4 陌生文件未被删除" || _bad "AC-1.4 陌生文件未被删除" "notes.txt 不见了"

# ---- AC-1.5 sagy 自己管理的条目仍严格校验 ----
rm -rf "$SAGY_ROOT"; mkdir -p "$SAGY_ROOT"
sagy_run login --token "$FRESH_JWT" --email t1b@example.com >/dev/null 2>&1
mv "$SAGY_ROOT/state.json" "$SBX/real-state.json"
ln -s "$SBX/real-state.json" "$SAGY_ROOT/state.json"
OUT="$(sagy_run list 2>&1)"; RC=$?
[ "$RC" != "0" ] && _ok "AC-1.5 state.json 是 symlink 时仍被拒绝" || _bad "AC-1.5 state.json 是 symlink 时仍被拒绝" "rc=0"
rm -f "$SAGY_ROOT/state.json"; mv "$SBX/real-state.json" "$SAGY_ROOT/state.json"
rm -rf "$SAGY_ROOT/accounts"; printf 'not a dir\n' > "$SAGY_ROOT/accounts"
OUT="$(sagy_run list 2>&1)"; RC=$?
[ "$RC" != "0" ] && _ok "AC-1.5 accounts 是普通文件时仍被拒绝" || _bad "AC-1.5 accounts 是普通文件时仍被拒绝" "rc=0"

# ---- AC-2 当前工作目录不是安全边界 ----
rm -rf "$SAGY_ROOT"; mkdir -p "$SAGY_ROOT"
sagy_run list >/dev/null 2>&1
OUT="$(sagy_run_in "$SAGY_ROOT" list 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-2.1 cwd 在 state root 内时 sagy list 成功"
assert_not_contains "$OUT" "protected system directory" "AC-2.1 不报 protected system directory"
OUT="$(sagy_run_in "$SBX/agcli" list 2>&1)"; RC=$?
assert_eq "0" "$RC" "AC-2.2 cwd 在 ANTIGRAVITY_CONFIG_DIR 时 sagy list 成功"

OUT="$(HOME="$SBX/home" ANTIGRAVITY_CONFIG_DIR="$SBX/agcli" GEMINI_HOME="$SBX/gemini" \
  PATH="$SBX/bin:$PATH" "$REPO_ROOT/target/release/sagy" --state-dir "$SBX/home" list 2>&1)"; RC=$?
[ "$RC" != "0" ] && _ok "AC-2.3 把 \$HOME 本身当 state root 仍被拒绝" || _bad "AC-2.3 把 \$HOME 本身当 state root 仍被拒绝" "rc=0"

# ---- AC-4 既有宽权限凭据要迁移收紧 (仅 Unix) ----
rm -rf "$SAGY_ROOT"; mkdir -p "$SAGY_ROOT"
sagy_run login --token "$FRESH_JWT" --email t1c@example.com >/dev/null 2>&1
CRED="$(find "$SAGY_ROOT/accounts" -type f | head -1)"
if [ -n "$CRED" ]; then
  chmod 0644 "$CRED"; chmod 0755 "$SAGY_ROOT/accounts"
  sagy_run list >/dev/null 2>&1
  assert_file_mode "$CRED" "600" "AC-4.1 旧的 0644 凭据文件被收紧回 0600"
  assert_file_mode "$SAGY_ROOT/accounts" "700" "AC-4.1 旧的 0755 accounts 目录被收紧回 0700"
else
  _bad "AC-4.1 旧权限迁移" "找不到凭据文件, 无法验证"
fi

report
