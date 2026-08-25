#!/usr/bin/env bash
# T7 验收: CLI 表面 (死参数 / 真实 help / -m 等价 / 透传)
source "$(dirname "$0")/lib.sh"
source "$(dirname "$0")/fixtures.sh"
echo "== T7 验收: CLI 表面 =="
build_release
sbx_init

# 把出网流量指向必定拒绝连接的地址: 让健康探测走离线分支, 使 launch 路径在沙箱中可判定
offline_run() {
  HTTPS_PROXY="http://127.0.0.1:1" HTTP_PROXY="http://127.0.0.1:1" ALL_PROXY="http://127.0.0.1:1" \
  https_proxy="http://127.0.0.1:1" http_proxy="http://127.0.0.1:1" all_proxy="http://127.0.0.1:1" \
  sagy_run "$@"
}

offline_run login --token "$FRESH_JWT" --email cli@example.com >/dev/null 2>&1

# ---- AC-1.1 --all 必须已被删除 ----
OUT="$(sagy_run push --all file://$SBX/nope.git 2>&1)"
case "$OUT" in
  *"unexpected argument"*|*"--all"*"not"*|*"Unknown"*) _ok "AC-1.1 sagy push --all 被 clap 判为未知参数" ;;
  *) _bad "AC-1.1 sagy push --all 被 clap 判为未知参数" "$OUT" ;;
esac
OUT="$(sagy_run pull --all file://$SBX/nope.git 2>&1)"
case "$OUT" in
  *"unexpected argument"*|*"--all"*"not"*|*"Unknown"*) _ok "AC-1.1 sagy pull --all 被 clap 判为未知参数" ;;
  *) _bad "AC-1.1 sagy pull --all 被 clap 判为未知参数" "$OUT" ;;
esac

# ---- AC-2.2 / AC-2.3 真实 help ----
OUT="$(sagy_run --help 2>&1)"
assert_contains "$OUT" "--state-dir" "AC-2.3 顶层 help 里有 --state-dir 说明"
OUT="$(sagy_run help launch 2>&1)"
assert_contains "$OUT" "Usage: sagy launch" "AC-2.2 sagy help launch 输出真实 clap 帮助"
OUT="$(sagy_run push --help 2>&1)"
assert_contains "$OUT" "--insecure-host-key" "AC-2.2 push 的真实 help 列出 --insecure-host-key"

# ---- AC-2.4 -- 之后的参数原样透传 ----
: > "$FAKE_AGY_LOG"
offline_run launch -- --help >/dev/null 2>&1
ARGV="$(agy_argv)"
assert_contains "$ARGV" "--help" "AC-2.4 -- 之后的 --help 透传给了 agy"

# ---- AC-4 -m 与 --model 等价, 不得重复注入默认模型 ----
: > "$FAKE_AGY_LOG"; offline_run launch -- -m custom-model >/dev/null 2>&1
ARGV="$(agy_argv)"
assert_contains "$ARGV" "-m custom-model" "AC-4.2 -m 被透传"
assert_not_contains "$ARGV" "--model gemini" "AC-4.1 -m 指定后不再注入默认 --model"
: > "$FAKE_AGY_LOG"; offline_run launch -- --model=custom-model >/dev/null 2>&1
ARGV="$(agy_argv)"
assert_not_contains "$ARGV" "--model gemini" "AC-4.2 --model=value 指定后不再注入默认 --model"
: > "$FAKE_AGY_LOG"; offline_run launch >/dev/null 2>&1
ARGV="$(agy_argv)"
assert_contains "$ARGV" "--model" "AC-4.3 未指定模型时仍注入默认模型"

# ---- AC-4.1 死帮助实现必须删除 ----
assert_grep_absent 'fn render_topic_help' "$REPO_ROOT/src" "AC-2.1 死的 render_topic_help 已删除"

report
