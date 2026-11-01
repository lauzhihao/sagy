#!/usr/bin/env bash
# 将同一个 Rust 程序安装成三个入口，升级时保留已有账号目录。
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin ]]; then
  echo "Native subscription profiles require macOS." >&2
  exit 1
fi
export ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
export GEMINI_HOME=/tmp/sagy-canary
cargo build --release --locked --bin sagy
bin_dir="${INSTALL_BIN:-$HOME/.local/bin}"
mkdir -p "$bin_dir"
stage="$(mktemp -d "$bin_dir/.sagy-install.XXXXXX")"
trap 'rm -f "$stage/sagy-profile" "$stage/sagy" "$stage/sagy-legacy"; rmdir "$stage"' EXIT
install -m 755 "${CARGO_TARGET_DIR:-target}/release/sagy" "$stage/sagy-profile"
for name in sagy sagy-legacy; do
  ln -s sagy-profile "$stage/$name"
done
for name in sagy-profile sagy sagy-legacy; do
  if [[ -d "$bin_dir/$name" ]]; then
    echo "Cannot replace directory: $bin_dir/$name" >&2
    exit 1
  fi
done
for name in sagy-profile sagy sagy-legacy; do
  mv -fh "$stage/$name" "$bin_dir/$name"
done
printf 'Installed native profile launcher in %s\n' "$bin_dir"
