#!/usr/bin/env bash
# AC: 自更新须校验 SHA256、须有超时、须禁止降级
source "$(dirname "$0")/lib.sh"
echo "== bugs-008 验收: 自更新完整性与降级防护 =="
UP="$REPO_ROOT/src/core/update.rs"

assert_grep_present 'SHA256SUMS' "$UP"                  "会下载 SHA256SUMS 清单"
assert_grep_present 'Sha256|sha2' "$UP"                 "会计算下载产物的 SHA-256"
assert_grep_present '\.timeout\(' "$UP"                 "HTTP client 设置了超时"
assert_grep_absent 'asset\.version == previous_version' "$UP" \
  "不再用字符串相等做版本比较"
assert_grep_present 'fn .*(compare|is_newer|parse_version)' "$UP" \
  "存在语义化版本比较函数"

report
