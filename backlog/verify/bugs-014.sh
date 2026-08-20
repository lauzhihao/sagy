#!/usr/bin/env bash
# AC: 清理死代码、旧别名安装残留与陈旧的 project map
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== bugs-014 验收: 残留清理 =="
build_release
sbx_init
sagy_run login --token "$FRESH_JWT" --email c@example.com >/dev/null 2>&1

# --- 1. 确认无调用的 public API 已删除 ---
for f in read_live_identity is_in_cooldown is_api_key is_vertex bin_dir runtime_dir \
         cli_about no_usable_account mark_needs_relogin; do
  assert_grep_absent "\\b$f\\b" "$REPO_ROOT/src" "死代码 $f 已删除"
done

# --- 2. 安装脚本会清理旧版本留下的别名二进制 ---
assert_grep_present 'remove_legacy_aliases' "$REPO_ROOT/install.sh" \
  "install.sh 定义并调用了 remove_legacy_aliases"
assert_grep_present 'Removed legacy model alias' "$REPO_ROOT/install.sh" \
  "install.sh 清理时会告知用户"
assert_grep_present 'Removed legacy model alias' "$REPO_ROOT/install.ps1" \
  "install.ps1 会清理旧别名二进制"

# --- 3. .project_map 已重新生成 ---
assert_grep_absent 'flash\.rs|pro\.rs|think\.rs|bin: flash' "$REPO_ROOT/.project_map" \
  ".project_map 不再列出已删除的 bin target"

# --- 4. 会话续接行为不得因重构而改变(行为锁, 不锁实现) ---
: > "$FAKE_AGY_LOG"; sagy_run >/dev/null 2>&1
assert_contains "$(agy_argv)" "--continue" "裸 sagy 仍注入 --continue"

: > "$FAKE_AGY_LOG"; sagy_run "some prompt" >/dev/null 2>&1
ARGV="$(agy_argv)"
assert_not_contains "$ARGV" "--continue" "sagy <prompt> 不注入 --continue"
assert_contains "$ARGV" "some prompt"     "sagy <prompt> 仍透传 prompt"

: > "$FAKE_AGY_LOG"; sagy_run launch -- --print "x" >/dev/null 2>&1
assert_not_contains "$(agy_argv)" "--continue" "--print 时不注入 --continue"

report
