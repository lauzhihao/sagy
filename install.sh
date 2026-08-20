#!/usr/bin/env bash
set -euo pipefail

REPO="${SAGY_REPO:-lauzhihao/sagy}"
SAGY_HOME="${SAGY_HOME:-${HOME}/.sagy}"
export SAGY_HOME
INSTALL_BIN="${INSTALL_BIN:-${SAGY_HOME}/bin}"
TMP_ROOT="${SAGY_HOME}/tmp"
WRAPPER_PATH="${INSTALL_BIN}/sagy"
ORIGINAL_WRAPPER_PATH="${INSTALL_BIN}/sagy-original"
VERSION="${SAGY_VERSION:-}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

show_requirements() {
  local missing=0
  local cmd
  echo "Dependency check:"
  for cmd in bash curl tar mktemp; do
    if need_cmd "${cmd}"; then
      printf '  [ok] %s -> %s\n' "${cmd}" "$(command -v "${cmd}")"
    else
      printf '  [missing] %s\n' "${cmd}" >&2
      missing=1
    fi
  done
  if [[ "${missing}" -ne 0 ]]; then
    echo "Install aborted because required commands are missing." >&2
    exit 1
  fi
}

detect_target() {
  local os arch
  os="$(uname -s 2>/dev/null || echo unknown)"
  arch="$(uname -m 2>/dev/null || echo unknown)"

  case "${os}/${arch}" in
    Darwin/arm64|Darwin/aarch64)
      echo "aarch64-apple-darwin"
      ;;
    Darwin/x86_64)
      echo "x86_64-apple-darwin"
      ;;
    Linux/x86_64|Linux/amd64)
      echo "x86_64-unknown-linux-musl"
      ;;
    *)
      echo "Unsupported platform: ${os}/${arch}" >&2
      echo "Use a published release asset manually or build from source with cargo." >&2
      exit 1
      ;;
  esac
}

resolve_version() {
  if [[ -n "${VERSION}" ]]; then
    echo "${VERSION}"
    return 0
  fi

  local api_url
  api_url="https://api.github.com/repos/${REPO}/releases/latest"
  VERSION="$(
    curl -fsSL "${api_url}" \
      | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  )"
  if [[ -z "${VERSION}" ]]; then
    echo "Failed to resolve latest release tag from ${api_url}" >&2
    exit 1
  fi
  echo "${VERSION}"
}

download_and_install() {
  local version target asset url tmp_dir cleanup_dir archive_path extracted_path
  version="$1"
  target="$2"
  asset="sagy-${version}-${target}.tar.gz"
  url="https://github.com/${REPO}/releases/download/${version}/${asset}"
  mkdir -p "${TMP_ROOT}"
  tmp_dir="$(mktemp -d "${TMP_ROOT}/install.XXXXXX")"
  cleanup_dir="${tmp_dir}"
  trap 'rm -rf -- "'"${cleanup_dir}"'"' EXIT
  archive_path="${tmp_dir}/${asset}"

  echo "Downloading ${url}"
  curl -fsSL "${url}" -o "${archive_path}"

  local sums_url sums_path expected_hash actual_hash
  sums_url="https://github.com/${REPO}/releases/download/${version}/SHA256SUMS.txt"
  sums_path="${tmp_dir}/SHA256SUMS.txt"
  if curl -fsSL "${sums_url}" -o "${sums_path}" 2>/dev/null; then
    echo "Verifying SHA256 checksum..."
    expected_hash="$(grep -F "${asset}" "${sums_path}" | awk '{print $1}' || true)"
    if [[ -n "${expected_hash}" ]]; then
      if need_cmd shasum; then
        actual_hash="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
      elif need_cmd sha256sum; then
        actual_hash="$(sha256sum "${archive_path}" | awk '{print $1}')"
      else
        actual_hash=""
      fi
      if [[ -n "${actual_hash}" && "${actual_hash}" != "${expected_hash}" ]]; then
        echo "Checksum mismatch for ${asset}! Expected: ${expected_hash}, got: ${actual_hash}" >&2
        exit 1
      fi
      echo "Checksum verified: ${expected_hash}"
    fi
  fi

  mkdir -p "${INSTALL_BIN}"
  tar -xzf "${archive_path}" -C "${tmp_dir}"
  extracted_path="${tmp_dir}/sagy"
  if [[ ! -f "${extracted_path}" ]]; then
    echo "Release archive did not contain a top-level sagy binary." >&2
    exit 1
  fi

  install -m 0755 "${extracted_path}" "${WRAPPER_PATH}"
}

install_original_wrapper() {
  cat > "${ORIGINAL_WRAPPER_PATH}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${AGY_BIN:-}" && -x "${AGY_BIN}" ]]; then
  exec "${AGY_BIN}" "$@"
fi
if [[ -x "${HOME}/.gemini/antigravity-cli/bin/agy" ]]; then
  exec "${HOME}/.gemini/antigravity-cli/bin/agy" "$@"
fi
if command -v agy >/dev/null 2>&1; then
  exec "$(command -v agy)" "$@"
fi
echo "agy not found on PATH or ~/.gemini/antigravity-cli/bin/agy." >&2
exit 1
EOF
  chmod 0755 "${ORIGINAL_WRAPPER_PATH}"
}

remove_legacy_aliases() {
  local legacy
  for legacy in flash pro think; do
    if [[ -f "${INSTALL_BIN}/${legacy}" ]]; then
      rm -f "${INSTALL_BIN}/${legacy}"
      echo "Removed legacy model alias ${INSTALL_BIN}/${legacy}"
    fi
  done
}

post_install_import() {
  if [[ -d "${HOME}/.gemini" ]]; then
    if "${WRAPPER_PATH}" import-known >/dev/null 2>&1; then
      echo "Imported current Antigravity credentials into sagy state."
    fi
  fi
}

print_next_steps() {
  echo "SAGY_HOME is ${SAGY_HOME}"
  echo "Installed to ${WRAPPER_PATH}"
  echo "Installed passthrough helper to ${ORIGINAL_WRAPPER_PATH}"
  if [[ ":$PATH:" != *":${INSTALL_BIN}:"* ]]; then
    echo
    echo "${INSTALL_BIN} is not currently on PATH."
    echo "Add this line to your shell profile (~/.zshrc or ~/.bashrc):"
    echo "  export PATH=\"${INSTALL_BIN}:\$PATH\""
  fi
}

show_requirements
TARGET="$(detect_target)"
VERSION="$(resolve_version)"
download_and_install "${VERSION}" "${TARGET}"
install_original_wrapper
remove_legacy_aliases
post_install_import
print_next_steps
