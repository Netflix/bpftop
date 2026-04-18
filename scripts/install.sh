#!/bin/sh
# bpftop installer
#
# Downloads a prebuilt bpftop binary from GitHub releases, verifies its
# SHA-256 against the digest reported by the GitHub releases API, and
# installs it to a directory on PATH.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/jfernandez/bpftop/main/scripts/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v0.8.0
#   curl -fsSL .../install.sh | sh -s -- --bin-dir /usr/local/bin
#
# Environment:
#   GITHUB_TOKEN  optional; raises the API rate limit from 60 to 5000/hour

set -eu

REPO="jfernandez/bpftop"
BIN_NAME="bpftop"

if [ -t 1 ]; then
    BOLD=$(printf '\033[1m')
    DIM=$(printf '\033[2m')
    RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m')
    RESET=$(printf '\033[0m')
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi

say()  { printf '%s\n' "$*"; }
info() { printf '%s==>%s %s\n' "${BOLD}" "${RESET}" "$*"; }
warn() { printf '%swarning:%s %s\n' "${YELLOW}" "${RESET}" "$*" >&2; }
err()  { printf '%serror:%s %s\n' "${RED}" "${RESET}" "$*" >&2; }
die()  { err "$*"; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

usage() {
    cat <<EOF
${BOLD}bpftop installer${RESET}

Downloads a prebuilt bpftop binary from GitHub releases and installs it.
The binary is verified against the SHA-256 digest reported by the GitHub
releases API. Installation aborts if verification fails.

${BOLD}Usage:${RESET}
  install.sh [--version <tag>] [--bin-dir <path>]

${BOLD}Options:${RESET}
  --version <tag>    Release tag to install (default: latest, e.g. v0.8.0)
  --bin-dir  <path>  Install directory (default: \$HOME/.local/bin, or
                     /usr/local/bin when run as root)
  -h, --help         Show this help

${BOLD}Environment:${RESET}
  GITHUB_TOKEN       Optional. Raises the GitHub API rate limit from 60 to
                     5000 requests/hour — useful on shared networks.

${BOLD}Notes:${RESET}
  bpftop requires Linux with BPF support and must be run with sudo.
EOF
}

detect_os() {
    uname_s=$(uname -s)
    case "$uname_s" in
        Linux) ;;
        *) die "unsupported OS: $uname_s (bpftop requires Linux)" ;;
    esac
}

detect_target() {
    uname_m=$(uname -m)
    case "$uname_m" in
        x86_64|amd64)  printf '%s\n' "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) printf '%s\n' "aarch64-unknown-linux-gnu" ;;
        *) die "unsupported architecture: $uname_m (supported: x86_64, aarch64)" ;;
    esac
}

github_api() {
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fsSL --proto '=https' --tlsv1.2 -H "Accept: application/vnd.github+json" \
             -H "Authorization: Bearer ${GITHUB_TOKEN}" "$1"
    else
        curl -fsSL --proto '=https' --tlsv1.2 -H "Accept: application/vnd.github+json" "$1"
    fi
}

extract_tag() {
    printf '%s\n' "$1" | awk -F'"' '/"tag_name":/ { print $4; exit }'
}

# The release binary is glibc-dynamic against libelf + libz. Warn (don't abort)
# if those aren't resolvable — NixOS users with nix-ld can run it despite ldd
# reporting "not found", so a hard failure would be wrong.
#
# Returns 0 when runtime libs are resolvable, 1 when any are missing.
check_runtime_libs() {
    binary="$1"
    command -v ldd >/dev/null 2>&1 || return 0

    missing=$(ldd "$binary" 2>/dev/null | awk '/not found/ { print $1 }') || return 0
    [ -z "$missing" ] && return 0

    # shellcheck disable=SC1091  # /etc/os-release is a system file; sourcing in a subshell contains its effects
    distro=$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")

    warn "missing runtime libraries — ${BIN_NAME} will fail to start until these are installed:"
    printf '%s\n' "$missing" | sed 's/^/    /' >&2
    case "$distro" in
        debian|ubuntu)
            printf '\n  fix: %ssudo apt install libelf1 zlib1g%s\n' "${BOLD}" "${RESET}" >&2 ;;
        fedora|rhel|centos|rocky|almalinux)
            printf '\n  fix: %ssudo dnf install elfutils-libelf zlib%s\n' "${BOLD}" "${RESET}" >&2 ;;
        alpine)
            printf '\n  fix: %ssudo apk add elfutils-libelf zlib%s\n' "${BOLD}" "${RESET}" >&2 ;;
        nixos)
            printf '\n  fix: the prebuilt binary is not supported on NixOS — install from nixpkgs instead:\n    %snix profile install nixpkgs#bpftop%s\n  (or build from source with %snix develop && cargo build --release%s for the latest version)\n' "${BOLD}" "${RESET}" "${BOLD}" "${RESET}" >&2 ;;
        *)
            cat >&2 <<EOF

  fix (pick your distro):
    Debian/Ubuntu: sudo apt install libelf1 zlib1g
    Fedora/RHEL:   sudo dnf install elfutils-libelf zlib
    Alpine:        sudo apk add elfutils-libelf zlib
    NixOS:         build from source in the flake dev shell
EOF
            ;;
    esac
    return 1
}

# Scan for the asset's name line, then grab the sha256 from the next digest line.
# Fails closed (empty output) if GitHub ever reorders these fields.
extract_digest() {
    release_json="$1"
    asset_name="$2"
    printf '%s\n' "$release_json" | awk -v target="\"name\": \"${asset_name}\"" '
        index($0, target) { found = 1; next }
        found && /"digest"[[:space:]]*:[[:space:]]*"sha256:/ {
            match($0, /sha256:[0-9a-f]+/)
            if (RSTART > 0) { print substr($0, RSTART + 7, RLENGTH - 7); exit }
        }
    '
}

VERSION=""
BIN_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --version)   [ $# -ge 2 ] || die "--version requires a value"; VERSION="$2"; shift 2 ;;
        --version=*) VERSION="${1#*=}"; shift ;;
        --bin-dir)   [ $# -ge 2 ] || die "--bin-dir requires a value";  BIN_DIR="$2";  shift 2 ;;
        --bin-dir=*) BIN_DIR="${1#*=}"; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

need_cmd uname
need_cmd curl
need_cmd install
need_cmd mktemp
need_cmd sha256sum
need_cmd awk

detect_os
TARGET=$(detect_target)

if [ -z "$BIN_DIR" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        BIN_DIR="/usr/local/bin"
    else
        BIN_DIR="${HOME}/.local/bin"
    fi
fi

if [ -n "$VERSION" ]; then
    API_URL="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
else
    API_URL="https://api.github.com/repos/${REPO}/releases/latest"
fi

info "fetching release metadata..."
RELEASE_JSON=$(github_api "$API_URL") || die "failed to fetch ${API_URL}
  — check network, or set GITHUB_TOKEN to raise the API rate limit"

if [ -z "$VERSION" ]; then
    VERSION=$(extract_tag "$RELEASE_JSON")
    [ -n "$VERSION" ] || die "could not parse tag_name from API response"
fi

ASSET="${BIN_NAME}-${TARGET}"
EXPECTED_SHA=$(extract_digest "$RELEASE_JSON" "$ASSET")
[ -n "$EXPECTED_SHA" ] || die "no sha256 digest found for ${ASSET} in ${VERSION}
  — release may be missing this target, or API response format changed"

URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

info "installing ${BOLD}${BIN_NAME} ${VERSION}${RESET} (${TARGET}) to ${BOLD}${BIN_DIR}${RESET}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

say "${DIM}downloading ${URL}${RESET}"
curl -fsSL --proto '=https' --tlsv1.2 -o "${TMPDIR}/${BIN_NAME}" "$URL" \
    || die "download failed — check that ${VERSION} publishes ${ASSET}"

say "${DIM}verifying sha256 ${EXPECTED_SHA}${RESET}"
printf '%s  %s\n' "$EXPECTED_SHA" "${TMPDIR}/${BIN_NAME}" \
    | sha256sum -c - >/dev/null 2>&1 \
    || die "sha256 verification FAILED — refusing to install a tampered or corrupt binary"

mkdir -p "$BIN_DIR" 2>/dev/null \
    || die "cannot create ${BIN_DIR} (try --bin-dir or re-run with sudo)"

install -m 0755 "${TMPDIR}/${BIN_NAME}" "${BIN_DIR}/${BIN_NAME}" 2>/dev/null \
    || die "cannot write to ${BIN_DIR} (try --bin-dir or re-run with sudo)"

printf '%sinstalled:%s %s/%s\n' "${GREEN}" "${RESET}" "${BIN_DIR}" "${BIN_NAME}"

if check_runtime_libs "${BIN_DIR}/${BIN_NAME}"; then
    case ":${PATH:-}:" in
        *":${BIN_DIR}:"*) ;;
        *) warn "${BIN_DIR} is not in your PATH — add this to your shell profile:
    export PATH=\"${BIN_DIR}:\$PATH\"" ;;
    esac

    cat <<EOF

${BOLD}Run it:${RESET}
  sudo ${BIN_DIR}/${BIN_NAME}

bpftop requires root because it issues BPF syscalls. If ${BIN_DIR} is on your
PATH but 'sudo bpftop' fails, your sudo policy is resetting PATH — invoke it
by full path (above) or use 'sudo env "PATH=\$PATH" ${BIN_NAME}'.
EOF
fi
