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
CURL_CONNECT_TIMEOUT="${SAGY_CURL_CONNECT_TIMEOUT:-10}"
CURL_MAX_TIME="${SAGY_CURL_MAX_TIME:-120}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

validate_release_component() {
  local value="$1" label="$2"
  if [[ -z "${value}" || ! "${value}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || "${value}" == "." || "${value}" == ".." ]]; then
    echo "Unsafe ${label}: ${value}" >&2
    return 1
  fi
}

validate_configuration() {
  if [[ ! "${REPO}" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    echo "Unsafe GitHub repository name: ${REPO}" >&2
    return 1
  fi
  local repo_owner="${REPO%%/*}" repo_name="${REPO#*/}"
  if [[ "${repo_owner}" == "." || "${repo_owner}" == ".." || "${repo_name}" == "." || "${repo_name}" == ".." ]]; then
    echo "Unsafe GitHub repository name: ${REPO}" >&2
    return 1
  fi
  if [[ -n "${VERSION}" ]]; then
    validate_release_component "${VERSION}" "release version"
  fi
  if [[ ! "${CURL_CONNECT_TIMEOUT}" =~ ^[1-9][0-9]*$ ]]; then
    echo "SAGY_CURL_CONNECT_TIMEOUT must be a positive integer." >&2
    return 1
  fi
  if [[ ! "${CURL_MAX_TIME}" =~ ^[1-9][0-9]*$ ]]; then
    echo "SAGY_CURL_MAX_TIME must be a positive integer." >&2
    return 1
  fi
}

show_requirements() {
  local missing=0
  local cmd
  echo "Dependency check:"
  for cmd in bash curl tar mktemp awk tr; do
    if need_cmd "${cmd}"; then
      printf '  [ok] %s -> %s\n' "${cmd}" "$(command -v "${cmd}")"
    else
      printf '  [missing] %s\n' "${cmd}" >&2
      missing=1
    fi
  done
  if need_cmd shasum || need_cmd sha256sum; then
    printf '  [ok] %s\n' "$(need_cmd shasum && echo shasum || echo sha256sum)"
  else
    echo '  [missing] shasum or sha256sum' >&2
    missing=1
  fi
  if [[ "${missing}" -ne 0 ]]; then
    echo "Install aborted because required commands are missing." >&2
    exit 1
  fi
}

download_file() {
  local url="$1" output="$2" status
  status="$(curl -fsSL --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time "${CURL_MAX_TIME}" \
    -w '%{http_code}' "${url}" -o "${output}")" || {
    echo "Download failed: ${url}" >&2
    return 1
  }
  if [[ ! "${status}" =~ ^2[0-9]{2}$ ]]; then
    echo "Download returned HTTP ${status:-unknown}: ${url}" >&2
    return 1
  fi
}

verify_checksum() {
  local sums_path="$1" archive_path="$2" asset="$3"
  local line hash file extra expected_hash actual_hash target_count=0 seen_files="" seen_file

  if [[ -L "${sums_path}" || ! -f "${sums_path}" || ! -s "${sums_path}" ]]; then
    echo "Checksum manifest is missing or empty: ${sums_path}" >&2
    return 1
  fi
  if [[ -L "${archive_path}" || ! -f "${archive_path}" || ! -s "${archive_path}" ]]; then
    echo "Downloaded archive is missing or empty: ${archive_path}" >&2
    return 1
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line//[[:space:]]/}" ]] && continue
    hash=""
    file=""
    extra=""
    read -r hash file extra <<< "${line}"
    if [[ -z "${hash}" || -z "${file}" || -n "${extra}" ]]; then
      echo "Malformed checksum entry in ${sums_path}." >&2
      return 1
    fi
    if [[ ! "${hash}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
      echo "Invalid SHA-256 checksum in ${sums_path}." >&2
      return 1
    fi
    if [[ "${file}" == \** ]]; then
      file="${file#\*}"
    fi
    if [[ -z "${file}" ]]; then
      echo "Empty checksum target in ${sums_path}." >&2
      return 1
    fi
    if [[ ! "${file}" =~ ^[A-Za-z0-9._-]+$ ]]; then
      echo "Unsafe checksum target in ${sums_path}." >&2
      return 1
    fi
    while IFS= read -r seen_file; do
      if [[ "${seen_file}" == "${file}" ]]; then
        echo "Duplicate checksum target in ${sums_path}." >&2
        return 1
      fi
    done <<< "${seen_files}"
    seen_files+="${file}"$'\n'
    if [[ "${file}" == "${asset}" ]]; then
      target_count=$((target_count + 1))
      expected_hash="${hash}"
    fi
  done < "${sums_path}"

  if [[ "${target_count}" -ne 1 ]]; then
    echo "Checksum entry for ${asset} is missing or duplicated." >&2
    return 1
  fi

  if need_cmd shasum; then
    actual_hash="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
  elif need_cmd sha256sum; then
    actual_hash="$(sha256sum "${archive_path}" | awk '{print $1}')"
  else
    echo "Checksum verification requires shasum or sha256sum." >&2
    return 1
  fi
  if [[ ! "${actual_hash}" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "Hash tool returned an invalid SHA-256 digest." >&2
    return 1
  fi
  if [[ "$(printf '%s' "${actual_hash}" | tr '[:upper:]' '[:lower:]')" != "$(printf '%s' "${expected_hash}" | tr '[:upper:]' '[:lower:]')" ]]; then
    echo "Checksum mismatch for ${asset}! Expected: ${expected_hash}, got: ${actual_hash}" >&2
    return 1
  fi
  echo "Checksum verified: ${expected_hash}"
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
    curl -fsSL --connect-timeout "${CURL_CONNECT_TIMEOUT}" --max-time "${CURL_MAX_TIME}" "${api_url}" \
      | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  )"
  if [[ -z "${VERSION}" ]]; then
    echo "Failed to resolve latest release tag from ${api_url}" >&2
    exit 1
  fi
  validate_release_component "${VERSION}" "release version"
  echo "${VERSION}"
}

download_and_install() {
  local version target asset url tmp_dir cleanup_dir archive_path extracted_path
  version="$1"
  target="$2"
  asset="sagy-${version}-${target}.tar.gz"
  validate_release_component "${version}" "release version"
  validate_release_component "${asset}" "release asset name"
  url="https://github.com/${REPO}/releases/download/${version}/${asset}"
  mkdir -p "${TMP_ROOT}"
  tmp_dir="$(mktemp -d "${TMP_ROOT}/install.XXXXXX")"
  cleanup_dir="${tmp_dir}"
  trap 'rm -rf -- "'"${cleanup_dir}"'"' EXIT
  archive_path="${tmp_dir}/${asset}"

  echo "Downloading ${url}"
  download_file "${url}" "${archive_path}"

  local sums_url sums_path
  sums_url="https://github.com/${REPO}/releases/download/${version}/SHA256SUMS.txt"
  sums_path="${tmp_dir}/SHA256SUMS.txt"
  echo "Verifying SHA256 checksum..."
  download_file "${sums_url}" "${sums_path}"
  verify_checksum "${sums_path}" "${archive_path}" "${asset}"

  mkdir -p "${INSTALL_BIN}"
  tar -xzf "${archive_path}" -C "${tmp_dir}"
  extracted_path="${tmp_dir}/sagy"
  if [[ -L "${extracted_path}" || ! -f "${extracted_path}" ]]; then
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

validate_configuration
show_requirements
TARGET="$(detect_target)"
VERSION="$(resolve_version)"
download_and_install "${VERSION}" "${TARGET}"
install_original_wrapper
remove_legacy_aliases
post_install_import
print_next_steps
