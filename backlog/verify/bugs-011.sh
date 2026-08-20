#!/usr/bin/env bash
# AC: 默认必须校验 SSH host key; 关闭校验只能是显式 opt-in 且必须告警
source "$(dirname "$0")/lib.sh"
echo "== bugs-011 验收: SSH host key 校验默认开启 =="
RS="$REPO_ROOT/src/adapters/antigravity/repo_sync.rs"
AR="$REPO_ROOT/src/cli/args.rs"

# 关闭校验的字符串只允许出现一次, 且必须在显式 opt-in 分支里
N="$(grep -c 'StrictHostKeyChecking=no' "$RS")"
assert_eq "1" "$N" "StrictHostKeyChecking=no 只出现在唯一的 opt-in 分支"
assert_grep_present 'insecure.host.key' "$AR"  "存在显式的 --insecure-host-key 参数"
assert_grep_present 'WARNING|警告'       "$RS"  "启用 opt-in 时会打印告警"
# 默认路径不得携带该选项
assert_grep_absent 'IdentitiesOnly=yes -o StrictHostKeyChecking=no' "$RS" \
  "默认 GIT_SSH_COMMAND 不再无条件关闭校验"

report
