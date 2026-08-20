#!/usr/bin/env bash
# AC: cargo test 不得写入任何真实凭据目录
source "$(dirname "$0")/lib.sh"
echo "== bugs-001 验收: cargo test 不污染凭据目录 =="
sbx_init

CANARY_AGCLI="$SBX/canary-agcli"
CANARY_GEMINI="$SBX/canary-gemini"
mkdir -p "$CANARY_AGCLI" "$CANARY_GEMINI"

# 把凭据目录指向空的 canary。若测试代码有隔离, canary 应保持为空。
( cd "$REPO_ROOT" && \
  ANTIGRAVITY_CONFIG_DIR="$CANARY_AGCLI" GEMINI_HOME="$CANARY_GEMINI" \
  cargo test 2>&1 | tail -20 )
TEST_EXIT=${PIPESTATUS[0]:-0}

assert_no_files_in "$CANARY_AGCLI"  "cargo test 未向 ANTIGRAVITY_CONFIG_DIR 写入文件"
assert_no_files_in "$CANARY_GEMINI" "cargo test 未向 GEMINI_HOME 写入文件"

# 源码层面: 测试代码不得直接调用 switch_account
assert_grep_absent 'adapter\.switch_account' "$REPO_ROOT/src/adapters/antigravity/auth.rs" \
  "auth.rs 的测试不再直接调用 switch_account"

report
