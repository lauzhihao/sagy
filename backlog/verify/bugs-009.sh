#!/usr/bin/env bash
# AC: sync_sibling_binaries 不得自拷贝(macOS 上 fs::copy(p,p) 会把文件清零)
source "$(dirname "$0")/lib.sh"
echo "== bugs-009 验收: 同步别名二进制时的自拷贝守卫 =="
UP="$REPO_ROOT/src/core/update.rs"

assert_grep_present 'target_path *== *source_exe|source_exe *== *target_path|canonicalize' "$UP" \
  "拷贝前判断了目标是否就是自身"

report
