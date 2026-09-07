#!/usr/bin/env bash
#
# Put the Lyntway command-line tools on a GitHub Actions runner.
#
# Downloads the release tarball for this runner's platform from the public
# lyntway-tools repository, checks it against the SHA256SUMS the same
# release published, unpacks it into $RUNNER_TEMP and adds that directory
# to the job's PATH.
#
# # What the checksum proves, and what it does not
#
# SHA256SUMS and the tarball come from the same release, so a match proves
# the bytes are the ones the release listed — a truncated download or a
# swapped CDN object fails here. It does not prove the release itself is
# ours: whoever could replace the tarball could replace the sums beside it.
# Pin LYNTWAY_SHA256 for that. The Homebrew formula carries a sum per
# platform taken from a published release, and a sum copied from there is
# a second, independent record of what the release contained.
#
# # Why this refuses rather than falling back
#
# A release without SHA256SUMS is installed by nobody rather than by
# everybody unchecked. The release that carried none (v0.1.1) predates this
# action; every release the action can use has to attach the file, and a
# missing one is a release process fault to fix at source, not here.
#
# Environment:
#   LYNTWAY_VERSION   "latest" or a version such as 0.2.0 (a leading v is fine)
#   LYNTWAY_SHA256    optional: the expected checksum of this platform's tarball
#   RUNNER_OS, RUNNER_ARCH, RUNNER_TEMP, GITHUB_PATH, GITHUB_OUTPUT   set by Actions
#
# Runs outside Actions too, for testing: the GITHUB_* files are written
# only when they are set.

set -euo pipefail

REPO="lynt-x-global/lyntway-tools"
RELEASES="https://github.com/$REPO/releases"

fail() {
  echo "::error::$*" >&2
  exit 1
}

case "${RUNNER_OS:-$(uname -s)}" in
  Linux|linux)  os=linux ;;
  macOS|Darwin) os=darwin ;;
  *) fail "lyntway is released for Linux and macOS runners; this one is ${RUNNER_OS:-$(uname -s)}" ;;
esac

case "${RUNNER_ARCH:-$(uname -m)}" in
  X64|x86_64|amd64)   arch=amd64 ;;
  ARM64|arm64|aarch64) arch=arm64 ;;
  *) fail "no lyntway build for architecture ${RUNNER_ARCH:-$(uname -m)}" ;;
esac

# "latest" is resolved through the redirect GitHub serves for
# /releases/latest, which needs no token and no JSON parser. The tag is
# what the redirect lands on; the API would say the same thing with more
# moving parts.
version="${LYNTWAY_VERSION:-latest}"
if [ "$version" = "latest" ]; then
  landed=$(curl -sSL -o /dev/null -w '%{url_effective}' "$RELEASES/latest")
  version="${landed##*/tag/}"
  [ "$version" != "$landed" ] && [ -n "$version" ] \
    || fail "could not find the latest release at $RELEASES/latest"
fi
version="${version#v}"
if ! printf '%s\n' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  fail "\"$version\" is not a release version (expected something like 0.2.0)"
fi

asset="lyntway_${version}_${os}_${arch}.tar.gz"
base="$RELEASES/download/v$version"
dest="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/lyntway-$version"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "downloading $asset from $base"
curl -sSLf --retry 3 -o "$work/$asset" "$base/$asset" \
  || fail "release v$version has no asset named $asset — see $RELEASES/tag/v$version"

if [ -n "${LYNTWAY_SHA256:-}" ]; then
  expected="$LYNTWAY_SHA256"
  source_of_truth="LYNTWAY_SHA256"
else
  curl -sSLf --retry 3 -o "$work/SHA256SUMS" "$base/SHA256SUMS" \
    || fail "release v$version published no SHA256SUMS, so the download cannot be checked; refusing to install it. Pin sha256 to install anyway."
  expected=$(awk -v a="$asset" '$2 == a {print $1}' "$work/SHA256SUMS")
  [ -n "$expected" ] || fail "SHA256SUMS for v$version does not list $asset"
  source_of_truth="the release's SHA256SUMS"
fi

# GitHub's Linux runners have sha256sum; macOS runners have shasum. Either
# prints the digest first, so one awk reads both.
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$work/$asset" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$work/$asset" | awk '{print $1}')
fi

if [ "$actual" != "$expected" ]; then
  fail "$asset does not match $source_of_truth (expected $expected, got $actual); not installing it"
fi
echo "checksum matches $source_of_truth"

rm -rf "$dest"
mkdir -p "$dest"
tar -xzf "$work/$asset" -C "$dest"
chmod +x "$dest/lyntway" "$dest/lyntway-verify" "$dest/lyntway-mcp"

# The binary reports the version stamped into it at build. A tarball whose
# contents disagree with its name is not one to run a check with.
built=$("$dest/lyntway" version) \
  || fail "the unpacked lyntway does not run on this runner ($os/$arch)"
[ "$built" = "$version" ] || [ "$built" = "v$version" ] \
  || fail "the tarball named $version contains lyntway $built"

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$dest" >> "$GITHUB_PATH"
fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "version=$version" >> "$GITHUB_OUTPUT"
  echo "path=$dest" >> "$GITHUB_OUTPUT"
fi
echo "installed lyntway $version to $dest"
