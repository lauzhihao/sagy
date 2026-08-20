#!/usr/bin/env bash
# AC: 所有落盘凭据文件权限为 0600, 目录为 0700
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== bugs-004 验收: 凭据文件权限 =="
build_release
sbx_init

sagy_run login --token "$FRESH_JWT" --email perm@example.com >/dev/null 2>&1
sagy_run login --api-key "AIzaFakeKey123" --email apiperm@example.com >/dev/null 2>&1

assert_file_mode "$(state_json)" "600" "state.json 权限为 0600"

BAD="$(find "$SBX/home/.sagy" -type f -perm +077 2>/dev/null | head -5)"
assert_eq "" "$BAD" "~/.sagy 下无 group/other 可读的文件"

BADDIR="$(find "$SBX/home/.sagy" -type d -perm +077 2>/dev/null | head -5)"
assert_eq "" "$BADDIR" "~/.sagy 下无 group/other 可访问的目录"

report
