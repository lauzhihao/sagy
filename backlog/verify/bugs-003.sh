#!/usr/bin/env bash
# AC: 三个别名注入的 model ID 必须与 agy models 的真实 ID 一致
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== bugs-003 验收: model ID 正确 =="
build_release
sbx_init
sagy_run login --token "$FRESH_JWT" --email m@example.com >/dev/null 2>&1

check_alias() { # 别名 期望model 不该出现的旧值
  : > "$FAKE_AGY_LOG"
  sagy_run_as "$1" >/dev/null 2>&1
  local argv; argv="$(agy_argv)"
  assert_contains "$argv" "$2" "$1 注入 $2"
  assert_not_contains "$argv" "$3" "$1 不再注入已失效的 $3"
}
check_alias flash "gemini-3.7-flash-low"  "gemini-3.7-flash "
check_alias think "gemini-3.7-flash-high" "gemini-3.7-flash "
check_alias pro   "gemini-3.1-pro-high"   "gemini-3.7-pro"

# 源码中不得再出现任何 agy models 里不存在的 ID
assert_grep_absent 'gemini-3\.7-pro' "$REPO_ROOT/src" "源码中不再出现 gemini-3.7-pro"

report
