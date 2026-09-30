#!/usr/bin/env bash
#
# Install a Lyntway agent on a Mac or a Linux machine.
#
# Two modes, chosen by how the script is invoked:
#
# 1. CLI agent (telemetry, receipts):
#      LYNTWAY_API_KEY=... bash install-agent.sh
#
# 2. On-device agent (HTTPS proxy, PII redaction, governance):
#      bash install-agent.sh --token TOKEN --api-base https://lyntway.com
#
# The CLI agent reports what AI tools are running and where traffic goes.
# The on-device agent intercepts HTTPS traffic, governs it (PII redaction,
# injection detection, content safety), and reports auditable receipts.
#
# # CLI agent
#
# Run as root (what an RMM does) and it installs for the whole machine: a
# launchd daemon or a systemd unit, state in /Library/Application
# Support/Lyntway or /var/lib/lyntway, readable by root only. Run as a
# person and it installs for them: a launchd agent or a systemd user unit,
# state in ~/.lyntway/agent.
#
# Why the key is an environment variable: an argument is visible to every
# user on the machine in `ps`, for as long as the process runs. An
# environment variable is visible only to the process's own user and root.
#
# The tarball is checked against SHA256SUMS the same release published.
#
# Environment:
#   LYNTWAY_API_KEY     required (CLI mode)
#   LYNTWAY_URL         optional: a self-hosted Lyntway (default https://lyntway.com)
#   LYNTWAY_AGENT_MODE  optional: laptop (default) or server
#   LYNTWAY_VERSION     optional: "latest" (default) or a version such as 0.3.0
#   LYNTWAY_SHA256      optional: the expected checksum of this platform's tarball
#
# # On-device agent
#
# Requires root. The enrollment token is single-use and expires in one hour;
# generate it from the console at /on-device.
#
# Arguments:
#   --token TOKEN       required: the enrollment token from the console
#   --api-base URL      required: the Lyntway server (e.g. https://lyntway.com)
#   --no-proxy          optional: skip system proxy configuration
#   --no-sidecar        optional: skip AI sidecar model download

set -euo pipefail

REPO="lynt-x-global/lyntway-tools"
RELEASES="https://github.com/$REPO/releases"

fail() {
  echo "lyntway install: $*" >&2
  exit 1
}

TOTAL_STEPS=8
step()  { printf '\n\033[1mStep %s of %s — %s\033[0m\n' "$1" "$TOTAL_STEPS" "$2"; }
info()  { printf '  \033[36m[info]\033[0m  %s\n' "$*"; }
ok()    { printf '  \033[32m  [ok]\033[0m  %s\n' "$*"; }
warn()  { printf '  \033[33m[warn]\033[0m  %s\n' "$*"; }

# ── Detect platform ───────────────────────────────────────────────────

case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) fail "this installer is for macOS and Linux; use install-agent.ps1 on Windows" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail "no lyntway build for $(uname -m)" ;;
esac

# ── Sidecar service definitions ──────────────────────────────────────

write_launchd_sidecar_plist() {
  local sidecar_dir="$1"
  cat > /Library/LaunchDaemons/com.lyntway.sidecar.plist <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.lyntway.sidecar</string>
  <key>ProgramArguments</key>
  <array>
    <string>$sidecar_dir/venv/bin/uvicorn</string>
    <string>app:app</string>
    <string>--host</string>
    <string>127.0.0.1</string>
    <string>--port</string>
    <string>8092</string>
  </array>
  <key>WorkingDirectory</key><string>$sidecar_dir</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>LYNTWAY_SIDECAR_PROFILE</key><string>$(cat "$sidecar_dir/.profile" 2>/dev/null || echo lean)</string>
    <key>VIRTUAL_ENV</key><string>$sidecar_dir/venv</string>
    <key>PATH</key><string>$sidecar_dir/venv/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/lyntway-sidecar.log</string>
  <key>StandardErrorPath</key><string>/var/log/lyntway-sidecar.log</string>
</dict>
</plist>
PLISTEOF
}

write_systemd_sidecar_unit() {
  local sidecar_dir="$1"
  local profile
  profile=$(cat "$sidecar_dir/.profile" 2>/dev/null || echo lean)
  cat > /etc/systemd/system/lyntway-sidecar.service <<UNITEOF
[Unit]
Description=Lyntway AI Sidecar
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$sidecar_dir
ExecStart=$sidecar_dir/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8092
Environment=LYNTWAY_SIDECAR_PROFILE=$profile
Environment=VIRTUAL_ENV=$sidecar_dir/venv
Environment=PATH=$sidecar_dir/venv/bin:/usr/local/bin:/usr/bin:/bin
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF
}

# ── On-device agent installation ─────────────────────────────────────

install_on_device() {
  [ -n "$API_BASE" ] || fail "--api-base is required with --token"
  [ "$(id -u)" -eq 0 ] || fail "the on-device agent must be installed as root (use sudo)"
  API_BASE="${API_BASE%/}"

  local ram_gb
  if [ "$os" = "darwin" ]; then
    ram_gb=$(( $(sysctl -n hw.memsize) / 1073741824 ))
  else
    ram_gb=$(awk '/MemTotal/{printf "%d", $2/1048576}' /proc/meminfo)
  fi
  info "detected $ram_gb GB RAM on $os/$arch"

  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT

  # Step 1: Download the on-device agent binary.

  step 1 "Download the on-device agent"

  local dl_base="${API_BASE}/dl/on-device"
  local binary="lyntway-agent_${os}_${arch}"
  curl -sSLf --retry 3 -o "$work/lyntway-agent" "$dl_base/$binary" \
    || fail "could not download the on-device agent from $dl_base/$binary"
  chmod +x "$work/lyntway-agent"
  ok "downloaded lyntway-agent for $os/$arch"

  # Step 2: Install to /usr/local/bin.

  step 2 "Install binary"

  local dest=/usr/local/bin
  install -m 0755 "$work/lyntway-agent" "$dest/lyntway-agent"
  ok "installed to $dest/lyntway-agent"

  # Step 3: Activate with enrollment token.
  # The token is single-use and expires in 1 hour. Activation returns a
  # persistent API key the agent uses for all subsequent communication.

  step 3 "Activate with enrollment token"

  local hostname_val
  hostname_val=$(hostname)
  local activate_resp
  activate_resp=$(curl -sSf -X POST "$API_BASE/v1/on-device/activate" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$ENROLL_TOKEN\",\"hostname\":\"$hostname_val\",\"os\":\"$os\",\"arch\":\"$arch\"}" 2>&1) \
    || fail "activation failed — the token may have expired or already been used"

  local api_key
  api_key=$(printf '%s' "$activate_resp" | grep -o '"api_key":"[^"]*"' | head -1 | cut -d'"' -f4)
  [ -n "$api_key" ] || fail "activation succeeded but no API key was returned"

  local machine_id
  machine_id=$(printf '%s' "$activate_resp" | grep -o '"machine_id":"[^"]*"' | head -1 | cut -d'"' -f4)

  # Write credentials to a root-only file.
  local state_dir=/var/lib/lyntway-agent
  mkdir -p "$state_dir"
  chmod 0700 "$state_dir"
  cat > "$state_dir/agent.env" <<ENVEOF
LYNTWAY_API_KEY=$api_key
LYNTWAY_API_BASE=$API_BASE
LYNTWAY_MACHINE_ID=$machine_id
ENVEOF
  chmod 0600 "$state_dir/agent.env"
  ok "activated as $machine_id"

  # Step 4: Install CA certificate.

  step 4 "Install MITM CA certificate"

  "$dest/lyntway-agent" --install-ca 2>/dev/null \
    || warn "CA installation needs manual attention — run: lyntway-agent --install-ca"
  ok "CA certificate installed to OS trust store"

  # Step 5: Configure system proxy.

  if [ "$NO_PROXY" = "false" ]; then
    step 5 "Enable system proxy"

    if [ "$os" = "darwin" ]; then
      for svc in $(networksetup -listallhardwareports | awk '/^Hardware Port:/{$1=$2=""; print}' | sed 's/^ *//'); do
        networksetup -setsecurewebproxy "$svc" 127.0.0.1 9090 2>/dev/null || true
        networksetup -setwebproxy "$svc" 127.0.0.1 9090 2>/dev/null || true
      done
      ok "system proxy set to 127.0.0.1:9090 (macOS)"
    else
      if command -v gsettings >/dev/null 2>&1; then
        gsettings set org.gnome.system.proxy mode manual 2>/dev/null || true
        gsettings set org.gnome.system.proxy.https host 127.0.0.1 2>/dev/null || true
        gsettings set org.gnome.system.proxy.https port 9090 2>/dev/null || true
        gsettings set org.gnome.system.proxy.http host 127.0.0.1 2>/dev/null || true
        gsettings set org.gnome.system.proxy.http port 9090 2>/dev/null || true
      fi
      cat > /etc/profile.d/lyntway-proxy.sh <<'PROXYEOF'
# BEGIN lyntway-agent proxy
export HTTPS_PROXY=http://127.0.0.1:9090
export HTTP_PROXY=http://127.0.0.1:9090
export NO_PROXY=localhost,127.0.0.1
# END lyntway-agent proxy
PROXYEOF
      chmod 0644 /etc/profile.d/lyntway-proxy.sh
      ok "system proxy set to 127.0.0.1:9090 (Linux)"
    fi
  else
    info "skipping proxy configuration (--no-proxy)"
  fi

  # Step 6: Register autostart.

  step 6 "Register autostart"

  if [ "$os" = "darwin" ]; then
    cat > /Library/LaunchDaemons/com.lyntway.agent.plist <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.lyntway.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$dest/lyntway-agent</string>
    <string>--daemon</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>LYNTWAY_API_KEY</key><string>$api_key</string>
    <key>LYNTWAY_API_BASE</key><string>$API_BASE</string>
    <key>LYNTWAY_MACHINE_ID</key><string>$machine_id</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/lyntway-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/lyntway-agent.log</string>
</dict>
</plist>
PLISTEOF
    launchctl load -w /Library/LaunchDaemons/com.lyntway.agent.plist 2>/dev/null || true
    ok "registered launchd daemon"
  else
    cat > /etc/systemd/system/lyntway-agent.service <<UNITEOF
[Unit]
Description=Lyntway On-Device Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$dest/lyntway-agent --daemon
EnvironmentFile=$state_dir/agent.env
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNITEOF
    systemctl daemon-reload
    systemctl enable --now lyntway-agent.service
    ok "registered and started systemd service"
  fi

  # Step 7: AI sidecar (on-device ML).
  #
  # RAM < 12 GB: skip (ONNX-only mode via the agent binary)
  # otherwise:   "lean" profile, ~4 GB of weights
  #
  # The sidecar is a Python FastAPI service that downloads its models on first
  # startup. We install the code, create a venv, and register it as a service
  # on 127.0.0.1:8092.
  #
  # It used to choose "full" at 16 GB of RAM or more, which is every laptop
  # sold in the last five years. The full tier pulls three multi-billion
  # parameter models at full precision — Phi-3 at 7.6 GB, two Granites at
  # 5 GB each — for about 24 GB in ~/.cache/huggingface on a machine that
  # belongs to somebody else and was not asked.
  #
  # RAM was the wrong question. It says whether a model can be held once it is
  # here, not whether 24 GB should be fetched onto a disk we do not own. The
  # detection this product exists for is entirely in the lean tier; the full
  # tier adds judges that belong on the gateway, where one copy serves
  # everybody. Set LYNTWAY_SIDECAR_PROFILE=full deliberately if you want them.

  if [ "$NO_SIDECAR" = "false" ] && [ "$ram_gb" -ge 12 ]; then
    step 7 "AI sidecar (on-device ML)"

    local profile="lean"
    info "sidecar profile: $profile (${ram_gb} GB RAM)"

    local sidecar_dir="$state_dir/sidecar"
    mkdir -p "$sidecar_dir"

    info "downloading sidecar package..."
    curl -sSLf --retry 3 -o /tmp/lw-sidecar.tar.gz "$dl_base/sidecar/sidecar.tar.gz" \
      || { warn "could not download sidecar package — skipping"; }

    if [ -f /tmp/lw-sidecar.tar.gz ]; then
      tar xzf /tmp/lw-sidecar.tar.gz -C "$sidecar_dir"
      rm -f /tmp/lw-sidecar.tar.gz
      ok "sidecar package extracted"

      # Python venv + dependencies.
      if command -v python3 >/dev/null 2>&1; then
        info "creating Python environment (this may take a few minutes)..."
        python3 -m venv "$sidecar_dir/venv"
        "$sidecar_dir/venv/bin/pip" install --quiet -r "$sidecar_dir/requirements.txt" \
          || warn "pip install had errors — sidecar may not start"

        # spaCy English model for NER.
        "$sidecar_dir/venv/bin/python" -m spacy download en_core_web_sm 2>/dev/null || true

        # Write a profile marker so the sidecar knows which tier to load.
        printf '%s' "$profile" > "$sidecar_dir/.profile"

        # Register as a system service.
        if [ "$os" = "darwin" ]; then
          write_launchd_sidecar_plist "$sidecar_dir"
          launchctl load -w /Library/LaunchDaemons/com.lyntway.sidecar.plist 2>/dev/null || true
        else
          write_systemd_sidecar_unit "$sidecar_dir"
          systemctl daemon-reload
          systemctl enable --now lyntway-sidecar.service 2>/dev/null || true
        fi

        # Wait for health — models download on first startup, so it may
        # take a while. Five probes at 3 s each is 15 s; if that isn't
        # enough, the sidecar is still starting and will be healthy later.
        local sidecar_ok=false
        for _i in 1 2 3 4 5; do
          if curl -sf http://127.0.0.1:8092/health >/dev/null 2>&1; then
            sidecar_ok=true
            break
          fi
          sleep 3
        done
        if [ "$sidecar_ok" = "true" ]; then
          local sc_profile
          sc_profile=$(curl -sf http://127.0.0.1:8092/health | grep -o '"profile":"[^"]*"' | cut -d'"' -f4)
          ok "sidecar running (profile: ${sc_profile:-$profile})"
        else
          warn "sidecar not yet healthy — models downloading in background"
        fi
      else
        warn "python3 not found — skipping sidecar (install Python 3.10+ and re-run)"
      fi
    fi
  elif [ "$NO_SIDECAR" = "true" ]; then
    info "skipping sidecar (--no-sidecar)"
  else
    info "skipping sidecar ($ram_gb GB RAM < 12 GB minimum)"
  fi

  # Step 8: Health check.

  step 8 "Verify"

  sleep 2
  local attempts=0
  local healthy=false
  while [ "$attempts" -lt 5 ]; do
    if curl -sf http://127.0.0.1:9090/health >/dev/null 2>&1; then
      healthy=true
      break
    fi
    sleep 1
    attempts=$((attempts + 1))
  done

  if [ "$healthy" = "true" ]; then
    ok "on-device agent is running on 127.0.0.1:9090"
  else
    warn "agent may still be starting — check: curl http://127.0.0.1:9090/health"
  fi

  printf '\n'
  printf '  \033[32m╭───────────────────────────────────────────────────────╮\033[0m\n'
  printf '  \033[32m│\033[0m   \033[1;32m✓\033[0m  LYNTWAY agent installed and active               \033[32m│\033[0m\n'
  printf '  \033[32m│\033[0m   Manage:    %s/on-device%*s\033[32m│\033[0m\n' "$API_BASE" "$((34 - ${#API_BASE}))" ""
  printf '  \033[32m│\033[0m   Status:    lyntway-agent --status                   \033[32m│\033[0m\n'
  printf '  \033[32m╰───────────────────────────────────────────────────────╯\033[0m\n'
  printf '\n'
}

# ── Parse arguments ───────────────────────────────────────────────────
# --token triggers on-device mode; no args triggers CLI mode.

ENROLL_TOKEN=""
API_BASE=""
NO_PROXY=false
NO_SIDECAR=false

while [ $# -gt 0 ]; do
  case "$1" in
    --token)      shift; ENROLL_TOKEN="${1:-}"; shift ;;
    --api-base)   shift; API_BASE="${1:-}"; shift ;;
    --no-proxy)   NO_PROXY=true; shift ;;
    --no-sidecar) NO_SIDECAR=true; shift ;;
    *) fail "unknown argument: $1" ;;
  esac
done

if [ -n "$ENROLL_TOKEN" ]; then
  install_on_device
  exit 0
fi

# ── CLI agent mode ────────────────────────────────────────────────────

[ -n "${LYNTWAY_API_KEY:-}" ] || fail "set LYNTWAY_API_KEY to the account's API key, or use --token TOKEN --api-base URL for the on-device agent"

mode="${LYNTWAY_AGENT_MODE:-laptop}"
case "$mode" in
  laptop) mode_flag="" ;;
  server) mode_flag="--server" ;;
  *) fail "LYNTWAY_AGENT_MODE is laptop or server, not \"$mode\"" ;;
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
# it to a file only root (or this user) can read.
# shellcheck disable=SC2086
"$dest/lyntway" agent install $mode_flag

echo
echo "What the agent collects: $dest/lyntway agent --explain"
