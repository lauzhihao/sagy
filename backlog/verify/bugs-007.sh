#!/usr/bin/env bash
# AC: 凭据不得出现在 URL query, 也不得被写进 state.json 的任何字段
source "$(dirname "$0")/lib.sh"
echo "== bugs-007 验收: 凭据不进 URL / 不落盘 =="
build_release
sbx_init
U="$REPO_ROOT/src/adapters/antigravity/usage.rs"

# 静态: URL 里不再拼凭据, 改用 header
assert_grep_absent '\?key=' "$U"        "探测 URL 中不再拼接 ?key="
assert_grep_absent 'access_token=' "$U" "探测 URL 中不再拼接 access_token="
assert_grep_present 'x-goog-api-key|Authorization' "$U" "改用 header 传递凭据"

# 行为: 无论探测成功还是失败, state.json 中不得出现凭据原文
SECRET="AIzaCanaryKeyDoNotLeak12345"
sagy_run login --api-key "$SECRET" --email leak@example.com >/dev/null 2>&1
sagy_run refresh >/dev/null 2>&1
ERRS="$(grep -o '"last_sync_error": "[^"]*"' "$(state_json)" | tr '\n' ' ')"
assert_not_contains "$ERRS" "$SECRET" "last_sync_error 中不含凭据原文"

report
