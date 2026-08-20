#!/usr/bin/env bash
# sagy 验收脚本公共库
# 用法: 在每个 bugs-NNN.sh 顶部 source 本文件
#
# 重要: 本库负责把所有会写真实凭据的路径重定向到沙箱。
# 任何验收脚本都不得在未 source 本库的情况下运行 sagy 或 cargo test。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SBX=""
PASS_COUNT=0
FAIL_COUNT=0

sbx_init() {
  SBX="$(mktemp -d "${TMPDIR:-/tmp}/sagy-verify.XXXXXX")"
  mkdir -p "$SBX/home" "$SBX/bin" "$SBX/agcli" "$SBX/gemini"
  # 假 agy: 把收到的 argv 与关键环境变量落盘, 退出码可通过 FAKE_AGY_EXIT 控制
  cat > "$SBX/bin/agy" <<'AGYEOF'
#!/bin/sh
echo "$*" > "$FAKE_AGY_LOG"
echo "GEMINI_API_KEY=${GEMINI_API_KEY:-<unset>}" >> "$FAKE_AGY_LOG"
exit "${FAKE_AGY_EXIT:-0}"
AGYEOF
  chmod +x "$SBX/bin/agy"
  export FAKE_AGY_LOG="$SBX/agy-argv.log"
  : > "$FAKE_AGY_LOG"
}

sbx_cleanup() { [ -n "$SBX" ] && rm -rf "$SBX"; }
trap sbx_cleanup EXIT

# 在沙箱中运行 sagy。真实 $HOME 与 ~/.gemini 不会被触碰。
sagy_run() {
  HOME="$SBX/home" \
  SAGY_HOME="$SBX/home/.sagy" \
  ANTIGRAVITY_CONFIG_DIR="$SBX/agcli" \
  GEMINI_HOME="$SBX/gemini" \
  FAKE_AGY_LOG="$FAKE_AGY_LOG" \
  FAKE_AGY_EXIT="${FAKE_AGY_EXIT:-0}" \
  PATH="$SBX/bin:$PATH" \
  "$REPO_ROOT/target/release/sagy" "$@"
}

# 以别名身份运行(flash/pro/think)
sagy_run_as() {
  local alias_name="$1"; shift
  cp "$REPO_ROOT/target/release/sagy" "$SBX/bin/$alias_name"
  HOME="$SBX/home" \
  SAGY_HOME="$SBX/home/.sagy" \
  ANTIGRAVITY_CONFIG_DIR="$SBX/agcli" \
  GEMINI_HOME="$SBX/gemini" \
  FAKE_AGY_LOG="$FAKE_AGY_LOG" \
  FAKE_AGY_EXIT="${FAKE_AGY_EXIT:-0}" \
  PATH="$SBX/bin:$PATH" \
  "$SBX/bin/$alias_name" "$@"
}

build_release() {
  ( cd "$REPO_ROOT" && cargo build --release 2>&1 | tail -3 )
  if [ ! -x "$REPO_ROOT/target/release/sagy" ]; then
    echo "BUILD FAILED: target/release/sagy 不存在"; exit 1
  fi
}

state_json() { echo "$SBX/home/.sagy/state.json"; }
agy_argv()   { head -n1 "$FAKE_AGY_LOG" 2>/dev/null || echo ""; }

# ---- 断言 ----
_ok()   { PASS_COUNT=$((PASS_COUNT+1)); printf '  [PASS] %s\n' "$1"; }
_bad()  { FAIL_COUNT=$((FAIL_COUNT+1)); printf '  [FAIL] %s\n' "$1"; [ -n "${2:-}" ] && printf '         实际: %s\n' "$2"; }

assert_eq() { # 期望值 实际值 说明
  if [ "$1" = "$2" ]; then _ok "$3"; else _bad "$3" "期望 [$1] 得到 [$2]"; fi
}
assert_contains() { # 字符串 子串 说明
  case "$1" in *"$2"*) _ok "$3";; *) _bad "$3" "[$1] 中不含 [$2]";; esac
}
assert_not_contains() {
  case "$1" in *"$2"*) _bad "$3" "[$1] 中出现了不该有的 [$2]";; *) _ok "$3";; esac
}
assert_file_mode() { # 文件 期望八进制权限 说明
  local m; m="$(stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null)"
  if [ "$m" = "$2" ]; then _ok "$3"; else _bad "$3" "$1 权限为 $m, 期望 $2"; fi
}
assert_no_files_in() { # 目录 说明
  local n; n="$(find "$1" -type f 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$n" = "0" ]; then _ok "$2"; else _bad "$2" "$1 下出现了 $n 个文件: $(find "$1" -type f)"; fi
}
assert_grep_absent() { # 正则 路径 说明
  if grep -rqE "$1" "$2" 2>/dev/null; then
    _bad "$3" "$(grep -rnE "$1" "$2" | head -3)"
  else _ok "$3"; fi
}
assert_grep_present() {
  if grep -rqE "$1" "$2" 2>/dev/null; then _ok "$3"
  else _bad "$3" "在 $2 中找不到匹配 $1 的内容"; fi
}

report() {
  echo
  echo "----------------------------------------"
  if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "RESULT: PASS  ($PASS_COUNT 项通过)"
    echo "----------------------------------------"
    exit 0
  else
    echo "RESULT: FAIL  ($PASS_COUNT 项通过, $FAIL_COUNT 项失败)"
    echo "----------------------------------------"
    exit 1
  fi
}
