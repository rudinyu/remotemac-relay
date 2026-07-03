#!/usr/bin/env bash
# install-linux.sh — one-shot installer for the RemoteMac server hosts on Linux.
#
# Installs the relay and/or the mesh coordinator as hardened systemd services.
# Idempotent: re-run to update the code or change the config.
#
#   sudo ./scripts/install-linux.sh                       # relay + coordinator
#   sudo ./scripts/install-linux.sh --relay-only
#   sudo REMOTEMAC_MESH_TOKEN=secret ./scripts/install-linux.sh --coord-only
#
# Flags:
#   --relay-only | --coord-only     install just one (default: both)
#   --relay-port N                  relay TCP port      (default 21118)
#   --coord-port N                  coordinator port    (default 21200, tcp+udp)
#   --token TOKEN                   mesh token (else $REMOTEMAC_MESH_TOKEN, else prompt/generate)
#   --prefix DIR                    install dir         (default /opt/remotemac)
#   --open-firewall                 open the ports with ufw/firewalld if present
#   -h | --help
set -euo pipefail

RELAY=1 COORD=1
RELAY_PORT=21118
COORD_PORT=21200
TOKEN="${REMOTEMAC_MESH_TOKEN:-}"
PREFIX=/opt/remotemac
OPEN_FW=0
ENV_DIR=/etc/remotemac
UNIT_DIR=/etc/systemd/system

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

ensure_cryptography() {  # the coordinator needs it (X25519 registration proof)
  if "$PY" -c 'import cryptography' 2>/dev/null; then return 0; fi
  log "installing python 'cryptography' (required by the coordinator)"
  if command -v apt-get >/dev/null; then
    apt-get update -qq >/dev/null 2>&1 || true
    apt-get install -y python3-cryptography >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null; then
    dnf install -y python3-cryptography >/dev/null 2>&1 || true
  fi
  if "$PY" -c 'import cryptography' 2>/dev/null; then return 0; fi
  "$PY" -m pip install --quiet cryptography >/dev/null 2>&1 || \
  "$PY" -m pip install --quiet --break-system-packages cryptography >/dev/null 2>&1 || true
  if "$PY" -c 'import cryptography' 2>/dev/null; then return 0; fi
  die "could not install 'cryptography' — install it manually (apt install python3-cryptography, or pip install cryptography) and re-run"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --relay-only)   COORD=0 ;;
    --coord-only)   RELAY=0 ;;
    --relay-port)   RELAY_PORT="${2:?}"; shift ;;
    --coord-port)   COORD_PORT="${2:?}"; shift ;;
    --token)        TOKEN="${2:?}"; shift ;;
    --prefix)       PREFIX="${2:?}"; shift ;;
    --open-firewall) OPEN_FW=1 ;;
    -h|--help)      sed -n '2,25p' "$0"; exit 0 ;;
    *)              die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# --- preflight ---------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "run as root (installs systemd services): sudo $0 …"
command -v systemctl >/dev/null || die "systemd (systemctl) not found — this installer targets systemd Linux"

# Source dir = repo root (parent of this script's dir).
SRC="$(cd "$(dirname "$0")/.." && pwd)"

PY="$(command -v python3 || true)"
[ -n "$PY" ] || die "python3 not found — install it first (e.g. apt install python3)"
"$PY" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,8) else 1)' \
  || die "python3 is too old — need 3.8+ (found: $("$PY" --version 2>&1))"

for f in relay.py coordinator.py remote_desktop.py; do
  [ -f "$SRC/$f" ] || die "missing $f in $SRC — run this from a checkout of the repo"
done

# --- install files -----------------------------------------------------------
log "installing into $PREFIX (python: $PY)"
install -d -m 755 "$PREFIX"
[ "$RELAY" -eq 1 ] && install -m 644 "$SRC/relay.py" "$PREFIX/relay.py"
if [ "$COORD" -eq 1 ]; then
  install -m 644 "$SRC/coordinator.py" "$PREFIX/coordinator.py"
  install -m 644 "$SRC/remote_desktop.py" "$PREFIX/remote_desktop.py"
fi

# --- relay service -----------------------------------------------------------
if [ "$RELAY" -eq 1 ]; then
  log "writing $UNIT_DIR/remotemac-relay.service (port $RELAY_PORT)"
  cat > "$UNIT_DIR/remotemac-relay.service" <<EOF
[Unit]
Description=RemoteMac rendezvous relay
After=network.target

[Service]
ExecStart=$PY $PREFIX/relay.py $RELAY_PORT
Restart=always
RestartSec=2
User=nobody
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
fi

# --- coordinator service (needs a token + a writable state dir) --------------
if [ "$COORD" -eq 1 ]; then
  ensure_cryptography
  if [ -z "$TOKEN" ]; then
    if [ -t 0 ]; then
      printf 'Mesh network token (blank = generate one): '
      read -rs TOKEN; printf '\n'
    fi
  fi
  if [ -z "$TOKEN" ]; then
    TOKEN="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(24))')"
    log "generated a mesh token — give this SAME value to every node:"
    printf '\n    %s\n\n' "$TOKEN"
  fi

  # Token in a root-only EnvironmentFile (systemd reads it as root, then drops privs).
  install -d -m 755 "$ENV_DIR"
  umask 077
  printf 'REMOTEMAC_MESH_TOKEN=%s\n' "$TOKEN" > "$ENV_DIR/coordinator.env"
  chmod 600 "$ENV_DIR/coordinator.env"
  umask 022

  log "writing $UNIT_DIR/remotemac-coordinator.service (port $COORD_PORT tcp+udp)"
  cat > "$UNIT_DIR/remotemac-coordinator.service" <<EOF
[Unit]
Description=RemoteMac mesh coordinator
After=network.target

[Service]
EnvironmentFile=$ENV_DIR/coordinator.env
ExecStart=$PY $PREFIX/coordinator.py $COORD_PORT --host 0.0.0.0 --state /var/lib/remotemac/coordinator-state.json
Restart=always
RestartSec=2
User=remotemac
DynamicUser=false
StateDirectory=remotemac
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  # A static, no-login system user owns the state directory (StateDirectory creates it).
  id remotemac >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin remotemac
fi

# --- enable + (re)start ------------------------------------------------------
log "reloading systemd and starting services"
systemctl daemon-reload
[ "$RELAY" -eq 1 ] && systemctl enable --now remotemac-relay.service
[ "$COORD" -eq 1 ] && systemctl enable --now remotemac-coordinator.service

# --- firewall (optional) -----------------------------------------------------
open_port() {  # $1=port $2=proto — best-effort; never aborts the installer
  if command -v ufw >/dev/null; then
    ufw allow "$1/$2" >/dev/null 2>&1 && log "ufw: opened $1/$2" || warn "ufw failed for $1/$2"
  elif command -v firewall-cmd >/dev/null; then
    firewall-cmd --add-port="$1/$2" --permanent >/dev/null 2>&1 \
      && log "firewalld: opened $1/$2" || warn "firewalld failed for $1/$2"
  else
    warn "no ufw/firewalld — open $1/$2 manually (and in any cloud security group)"
  fi
  return 0
}
if [ "$OPEN_FW" -eq 1 ]; then
  [ "$RELAY" -eq 1 ] && open_port "$RELAY_PORT" tcp
  [ "$COORD" -eq 1 ] && { open_port "$COORD_PORT" tcp; open_port "$COORD_PORT" udp; }
  command -v firewall-cmd >/dev/null && firewall-cmd --reload >/dev/null 2>&1 || true
fi

# --- summary -----------------------------------------------------------------
echo
log "done. status:"
[ "$RELAY" -eq 1 ] && systemctl --no-pager --lines=0 status remotemac-relay.service || true
[ "$COORD" -eq 1 ] && systemctl --no-pager --lines=0 status remotemac-coordinator.service || true
echo
log "next steps:"
[ "$RELAY" -eq 1 ] && echo "  • relay  listening on ${RELAY_PORT}/tcp"
[ "$COORD" -eq 1 ] && echo "  • coordinator on ${COORD_PORT}/tcp + ${COORD_PORT}/udp; nodes join with the token above"
[ "$OPEN_FW" -eq 0 ] && echo "  • open the port(s) in your firewall / cloud security group (or re-run with --open-firewall)"
echo "  • logs:  journalctl -u remotemac-relay -f   /   journalctl -u remotemac-coordinator -f"
