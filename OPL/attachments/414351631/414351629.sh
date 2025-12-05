#!/bin/sh
# install_new_openvpn.sh
# Script developed by Nelson Junior
# Created on: 2025-09-01
# Purpose:
#   - Install OpenVPN 2.6.14 on Ubuntu 20.04 (Focal)
#   - Add/fix OpenVPN repository
#   - Resolve GPG NO_PUBKEY 8E6DA8B4E158C569 (with fallback for 20.04)
#   - Install libssl-dev, liblzo2-dev, libpam0g-dev, and easy-rsa
#   - Lock the OpenVPN version after installation

set -eu

log()  { printf '[INFO] %s
' "$*"; }
warn() { printf '[WARN] %s
' "$*" >&2; }
err()  { printf '[ERROR] %s
' "$*" >&2; }

# ---------------- menu ----------------
echo "==============================="
echo "   OpenVPN Installation Menu   "
echo "==============================="
echo "1) Install OpenVPN 2.6.14"
echo "2) Exit"
printf "Choose an option [1-2]: "
read -r choice

case "$choice" in
  1) log "Starting OpenVPN 2.6.14 installation..." ;;
  2) log "Exiting. No installation performed."; exit 0 ;;
  *) err "Invalid option. Exiting."; exit 1 ;;
esac

# ---------------- root check ----------------
[ "$(id -u)" -eq 0 ] || { err 'Run as root: use sudo.'; exit 1; }

KEY_ID="8E6DA8B4E158C569"
KEYRING="/usr/share/keyrings/openvpn.gpg"
GLOBAL_TRUST_DIR="/etc/apt/trusted.gpg.d"
GLOBAL_TRUST_KEY="$GLOBAL_TRUST_DIR/openvpn.gpg"
REPO_FILE="/etc/apt/sources.list.d/openvpn-community-stable.list"
REPO_LINE_SIGNED='deb [signed-by=/usr/share/keyrings/openvpn.gpg] https://build.openvpn.net/debian/openvpn/stable focal main'
REPO_LINE_GLOBAL='deb https://build.openvpn.net/debian/openvpn/stable focal main'   # fallback without signed-by
OPENVPN_VER="2.6.14-focal0"
OPENVPN_FALLBACK="2.6.14-*"

# ---------------- utilities ----------------
ensure_dirs() {
  install -d -m 0755 "$(dirname "$KEYRING")"
  install -d -m 0755 "$GLOBAL_TRUST_DIR"
  install -d -m 0755 /root/.gnupg || true
  chmod 700 /root/.gnupg || true
}

prepare_gnupg() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y gnupg dirmngr ca-certificates >/dev/null 2>&1 || true
  [ -f /root/.gnupg/dirmngr.conf ] || : > /root/.gnupg/dirmngr.conf
}

write_repo_signed() { printf '%s
' "$REPO_LINE_SIGNED" > "$REPO_FILE"; }
write_repo_global() { printf '%s
' "$REPO_LINE_GLOBAL"  > "$REPO_FILE"; }

has_no_pubkey_error() { grep -q "NO_PUBKEY $KEY_ID" "$1"; }

apt_update_checked() {
  TMP=$(mktemp)
  if apt-get update -y >"$TMP" 2>&1; then
    rm -f "$TMP"; return 0
  fi
  cat "$TMP" >&2; echo "$TMP"; return 1
}

install_keyring_via_download() {
  log "Downloading official keyring and executing dearmor (signed-by)..."
  if curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg | gpg --dearmor > "$KEYRING" 2>/dev/null; then
    chmod 0644 "$KEYRING"; return 0
  fi
  if curl -fsSL https://packages.openvpn.net/packages-repo.gpg | gpg --dearmor > "$KEYRING" 2>/dev/null; then
    chmod 0644 "$KEYRING"; return 0
  fi
  return 1
}

install_keyring_via_keyserver() {
  log "Fetching key via keyserver and generating keyring (signed-by)..."
  GNUPGHOME=/root/.gnupg gpg --no-default-keyring --keyring /tmp/openvpn.gpg     --keyserver hkps://keyserver.ubuntu.com --recv-keys "$KEY_ID" 2>/dev/null || return 1
  GNUPGHOME=/root/.gnupg gpg --no-default-keyring --keyring /tmp/openvpn.gpg     --export "$KEY_ID" 2>/dev/null | gpg --dearmor > "$KEYRING" 2>/dev/null || return 1
  rm -f /tmp/openvpn.gpg || true
  chmod 0644 "$KEYRING"; return 0
}

install_global_key_via_apt_key() {
  log "Fallback method (apt-key add -) and repo without signed-by..."
  curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add - >/dev/null 2>&1 || return 1
  install -d -m 0755 "$(dirname "$GLOBAL_TRUST_KEY")"
  curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg | gpg --dearmor > "$GLOBAL_TRUST_KEY" 2>/dev/null || true
  chmod 0644 "$GLOBAL_TRUST_KEY" || true
  write_repo_global
  return 0
}

try_fix_keys_and_update() {
  ensure_dirs; prepare_gnupg
  write_repo_signed; rm -f "$KEYRING"

  if install_keyring_via_download || install_keyring_via_keyserver; then
    if apt-get update -y; then return 0; fi
  fi

  TMP=$(mktemp)
  if ! apt-get update -y >"$TMP" 2>&1; then
    if has_no_pubkey_error "$TMP"; then
      if install_global_key_via_apt_key && apt-get update -y; then rm -f "$TMP"; return 0; fi
    fi
    rm -f "$TMP"
  fi
  return 1
}

try_install_version() {
  ver="$1"
  if apt-get install -y "openvpn=${ver}"; then return 0; fi
  return 1
}

# ---------------- main flow ----------------
log 'apt-get update...'
if ! apt-get update -y; then
  warn 'apt-get update failed; fixing OpenVPN keyring...'
  if ! try_fix_keys_and_update; then err "apt-get update failed even after key fixes."; exit 1; fi
fi

log 'apt-get upgrade...'
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || true

log "Trying to install openvpn=${OPENVPN_VER}..."
if ! try_install_version "$OPENVPN_VER"; then
  warn "openvpn=${OPENVPN_VER} not available. Ensuring repo and keyring..."
  if ! try_fix_keys_and_update; then err "Failed to prepare OpenVPN repo/key."; exit 1; fi

  log "Installing openvpn ${OPENVPN_VER}..."
  if ! try_install_version "$OPENVPN_VER"; then
    warn "Could not install exactly ${OPENVPN_VER}. Trying ${OPENVPN_FALLBACK}..."
    if ! apt-get install -y "openvpn=${OPENVPN_FALLBACK}"; then err "Failed to find OpenVPN 2.6.14 in repository."; exit 2; fi
  fi
fi

log 'OpenVPN installed. Version:'
openvpn --version | head -n 1 || true

log 'Installing libraries libssl-dev liblzo2-dev libpam0g-dev and easy-rsa...'
DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev liblzo2-dev libpam0g-dev easy-rsa

log 'Applying hold on openvpn package...'
apt-mark hold openvpn || true
apt-mark showhold | grep -i openvpn || true

log 'Cleaning up orphan packages (autoremove)...'
apt-get autoremove -y || true

log 'Installation completed successfully.'
echo 'Summary:'
openvpn --version | head -n 1 || true
dpkg -l | egrep 'easy-rsa|libssl-dev|liblzo2-dev|libpam0g-dev' || true
