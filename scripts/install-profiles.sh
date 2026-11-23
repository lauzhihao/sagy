#!/usr/bin/env bash
# 安装唯一实体入口和一个兼容别名，升级时保留已有账号目录。
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin && "$(uname -s)" != Linux ]]; then
  echo "Native subscription profiles require macOS or Linux." >&2
  exit 1
fi
export ANTIGRAVITY_CONFIG_DIR=/tmp/sagy-canary
export GEMINI_HOME=/tmp/sagy-canary
bin_dir="${INSTALL_BIN:-$HOME/.local/bin}"
for name in sagy sagy-legacy sagy-profile; do
  path="$bin_dir/$name"
  if [[ -d "$path" && ! -L "$path" ]]; then
    echo "Cannot replace directory: $path" >&2
    exit 1
  fi
done
cargo build --release --locked --bin sagy
mkdir -p "$bin_dir"
stage="$(mktemp -d "$bin_dir/.sagy-install.XXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
install -m 755 "${CARGO_TARGET_DIR:-target}/release/sagy" "$stage/sagy"
ln -s sagy "$stage/sagy-legacy"
for name in sagy sagy-legacy; do
  case "$(uname -s)" in
    Darwin) mv -fh "$stage/$name" "$bin_dir/$name" ;;
    Linux) mv -fT "$stage/$name" "$bin_dir/$name" ;;
    *) echo "Unsupported platform for atomic installation." >&2; exit 1 ;;
  esac
done
# rm 删除旧链接本身，不会跟随指向外部文件或目录的链接。
rm -f -- "$bin_dir/sagy-profile"
printf 'Installed native profile launcher in %s\n' "$bin_dir"
