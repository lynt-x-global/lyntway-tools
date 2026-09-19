#!/usr/bin/env bash
#
# Install the Lyntway agent on a Mac or a Linux machine, from an RMM tool
# or by hand.
#
#   LYNTWAY_API_KEY=... bash install.sh
#
# Run as root (what an RMM does) and it installs for the whole machine: a
# launchd daemon or a systemd unit, state in /Library/Application
# Support/Lyntway or /var/lib/lyntway, readable by root only. Run as a
# person and it installs for them: a launchd agent or a systemd user unit,
# state in ~/.lyntway/agent.
#
# # Why the key is an environment variable
#
# An argument is visible to every user on the machine in `ps`, for as long
# as the process runs. An environment variable is visible only to the
# process's own user and root. This script accepts no key argument, and the
# binary refuses one.
#
# # What it checks
#
# The tarball against the SHA256SUMS the same release published, as the
# GitHub Action's installer does; pin LYNTWAY_SHA256 to check against a
# value you hold independently. The binaries are not yet code-signed; see
# README.md beside this file.
#
# Environment:
#   LYNTWAY_API_KEY     required: the account's API key
#   LYNTWAY_URL         optional: a self-hosted Lyntway (default https://lyntway.com)
#   LYNTWAY_AGENT_MODE  optional: laptop (default) or server
#   LYNTWAY_VERSION     optional: "latest" (default) or a version such as 0.3.0
#   LYNTWAY_SHA256      optional: the expected checksum of this platform's tarball

set -euo pipefail

REPO="lynt-x-global/lyntway-tools"
RELEASES="https://github.com/$REPO/releases"

fail() {
  echo "lyntway install: $*" >&2
  exit 1
}

[ $# -eq 0 ] || fail "this script takes no arguments; the key goes in LYNTWAY_API_KEY, where the process list cannot show it"
[ -n "${LYNTWAY_API_KEY:-}" ] || fail "set LYNTWAY_API_KEY to the account's API key"

mode="${LYNTWAY_AGENT_MODE:-laptop}"
case "$mode" in
  laptop) mode_flag="" ;;
  server) mode_flag="--server" ;;
  *) fail "LYNTWAY_AGENT_MODE is laptop or server, not \"$mode\"" ;;
esac

case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) fail "this installer is for macOS and Linux; use install.ps1 on Windows" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail "no lyntway build for $(uname -m)" ;;
esac

version="${LYNTWAY_VERSION:-latest}"
if [ "$version" = "latest" ]; then
  landed=$(curl -sSL -o /dev/null -w '%{url_effective}' "$RELEASES/latest")
  version="${landed##*/tag/}"
  [ "$version" != "$landed" ] && [ -n "$version" ] || fail "could not find the latest release at $RELEASES/latest"
fi
version="${version#v}"
printf '%s\n' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' \
  || fail "\"$version\" is not a release version"

asset="lyntway_${version}_${os}_${arch}.tar.gz"
base="$RELEASES/download/v$version"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "downloading $asset"
curl -sSLf --retry 3 -o "$work/$asset" "$base/$asset" || fail "release v$version has no $asset"
if [ -n "${LYNTWAY_SHA256:-}" ]; then
  expected="$LYNTWAY_SHA256"
else
  curl -sSLf --retry 3 -o "$work/SHA256SUMS" "$base/SHA256SUMS" \
    || fail "release v$version published no SHA256SUMS; refusing to install what cannot be checked"
  expected=$(awk -v a="$asset" '$2 == a {print $1}' "$work/SHA256SUMS")
  [ -n "$expected" ] || fail "SHA256SUMS does not list $asset"
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$work/$asset" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$work/$asset" | awk '{print $1}')
fi
[ "$actual" = "$expected" ] || fail "$asset does not match its checksum; not installing it"

tar -xzf "$work/$asset" -C "$work"

# Somewhere that survives a reboot and an upgrade of this script.
if [ "$(id -u)" -eq 0 ]; then
  dest=/usr/local/lib/lyntway
  install -d -m 0755 "$dest"
  install -m 0755 "$work/lyntway" "$dest/lyntway"
  ln -sf "$dest/lyntway" /usr/local/bin/lyntway
else
  dest="$HOME/.lyntway/bin"
  mkdir -p "$dest"
  install -m 0755 "$work/lyntway" "$dest/lyntway"
fi

built=$("$dest/lyntway" version) || fail "the downloaded lyntway does not run here ($os/$arch)"
echo "installed lyntway $built to $dest"

# The key reaches the agent through the environment, and the agent writes
# it to a file only root (or only this user) can read.
# shellcheck disable=SC2086
"$dest/lyntway" agent install $mode_flag

echo
echo "What the agent collects: $dest/lyntway agent --explain"
