#!/usr/bin/env bash
# AC: 移除只接收不生效的 --no-login 参数
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== bugs-015 验收: 移除空参数 --no-login =="
build_release
sbx_init

# 1. 源码中不再有 no_login 的任何痕迹
assert_grep_absent '\bno_login\b|--no-login' "$REPO_ROOT/src" "src 中不再出现 no_login"

# 2. 帮助文本不再宣传该参数
assert_grep_absent 'no-login' "$REPO_ROOT/src/cli/help.rs" "help 文本不再列出 --no-login"

# 3. 其余 launch 参数必须仍然可用(行为锁, 防止误删)
sagy_run login --token "$FRESH_JWT" --email n@example.com >/dev/null 2>&1
sagy_run --dry-run >/dev/null 2>&1
assert_eq "0" "$?" "--dry-run 仍可用"
sagy_run --no-launch >/dev/null 2>&1
assert_eq "0" "$?" "--no-launch 仍可用"
sagy_run --no-import-known --no-launch >/dev/null 2>&1
assert_eq "0" "$?" "--no-import-known 仍可用"
: > "$FAKE_AGY_LOG"; sagy_run --no-resume >/dev/null 2>&1
assert_not_contains "$(agy_argv)" "--continue" "--no-resume 仍生效"

# 4. auto 子命令不受影响
sagy_run auto --dry-run >/dev/null 2>&1
assert_eq "0" "$?" "sagy auto --dry-run 仍可用"

report
