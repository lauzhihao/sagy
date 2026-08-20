#!/usr/bin/env bash
# AC: 死代码与重复实现清理
source "$(dirname "$0")/lib.sh"
echo "== bugs-012 验收: 死代码与重复清理 =="

N="$(grep -c 'fn rewrite_alias_args\|fn rewrite_passthrough_launch_args' "$REPO_ROOT/src/cli/mod.rs")"
if [ "$N" -le 1 ]; then _ok "两个孪生 rewrite 函数已合并为一个"
else _bad "两个孪生 rewrite 函数已合并为一个" "仍存在 $N 个"; fi

assert_grep_absent 'if no_login \{[[:space:]]*return Ok\(None\);[[:space:]]*\}[[:space:]]*return Ok\(None\)' \
  "$REPO_ROOT/src/adapters/antigravity/mod.rs" "no_login 的空分支已清理"

assert_grep_absent 'fn test_find_git_bin' "$REPO_ROOT/src/adapters/antigravity/paths.rs" \
  "依赖宿主机环境的 test_find_git_bin 已移除"

assert_grep_absent '^#!\[allow\(dead_code\)\]' "$REPO_ROOT/src/core/state.rs" \
  "state.rs 的模块级 allow(dead_code) 已收窄"

report
