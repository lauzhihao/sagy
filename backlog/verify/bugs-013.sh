#!/usr/bin/env bash
# AC: 删除 flash/pro/think 三个别名入口, sagy 统一注入最新 flash 模型
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== bugs-013 验收: 移除模型别名, 统一默认模型 =="
build_release
sbx_init
sagy_run login --token "$FRESH_JWT" --email d@example.com >/dev/null 2>&1

MODEL="gemini-3.7-flash-high"

# 1. 裸 sagy 必须注入默认模型
: > "$FAKE_AGY_LOG"; sagy_run >/dev/null 2>&1
assert_contains "$(agy_argv)" "$MODEL" "裸 sagy 注入 $MODEL"

# 2. 带 prompt 的 sagy 也必须注入(走的是 passthrough 分支, 容易漏)
: > "$FAKE_AGY_LOG"; sagy_run "hello world" >/dev/null 2>&1
ARGV2="$(agy_argv)"
assert_contains "$ARGV2" "$MODEL"       "sagy <prompt> 同样注入 $MODEL"
assert_contains "$ARGV2" "hello world"  "sagy <prompt> 仍把 prompt 透传给 agy"

# 3. 用户显式指定 --model 时不得覆盖
: > "$FAKE_AGY_LOG"; sagy_run launch -- --model custom-model >/dev/null 2>&1
ARGV3="$(agy_argv)"
assert_contains "$ARGV3" "custom-model"      "用户显式 --model 被透传"
assert_not_contains "$ARGV3" "$MODEL"        "用户显式 --model 时不再注入默认模型"

# 4. 源码中不再有基于 argv[0] 的别名分发
assert_grep_absent 'exe_lower' "$REPO_ROOT/src"              "argv[0] 别名分发逻辑已删除"
assert_grep_absent 'rewrite_alias_args' "$REPO_ROOT/src"     "rewrite_alias_args 已删除"
assert_grep_absent 'sync_sibling_binaries' "$REPO_ROOT/src"  "sync_sibling_binaries 已删除(别名不存在了)"
assert_grep_absent 'gemini-3\.1-pro|gemini-3\.7-flash-low' "$REPO_ROOT/src" \
  "源码中不再出现 pro / low 档模型 ID"

# 5. 安装脚本不再铺设别名
assert_grep_absent 'FLASH_PATH|PRO_PATH|THINK_PATH' "$REPO_ROOT/install.sh"  "install.sh 不再安装别名"
assert_grep_absent 'flash\.exe|pro\.exe|think\.exe' "$REPO_ROOT/install.ps1" "install.ps1 不再安装别名"

# 6. 文档不再宣传别名入口
# 任何面向用户的文档都不得再提到这三个别名(表格、目录布局、正文皆算)
for doc in README.md README.zh-CN.md ARCHITECTURE.md CLAUDE.md; do
  assert_grep_absent '(flash|pro|think)\.rs|`flash`|`pro`|`think`|, flash, pro, think|flash, pro, think' \
    "$REPO_ROOT/$doc" "$doc 中不再提及已删除的别名入口"
done

report
