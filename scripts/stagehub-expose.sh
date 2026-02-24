#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/stagehub"
CONFIG_FILE="${INSTALL_DIR}/config.json"
STATE_DIR="/etc/stagehub"
STATE_FILE="${STATE_DIR}/expose-state.env"
SERVICE_NAME="stagehub.service"

CF_SERVICE_NAME="cloudflared.service"

log() {
  printf '[stagehub-expose] %s\n' "$*"
}

die() {
  printf '[stagehub-expose] ERROR: %s\n' "$*" >&2
  exit 1
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "Run as root (or via sudo)."
  fi
}

usage() {
  cat <<'USAGE'
Usage:
  stagehub expose status
  stagehub expose cloudflare enable [--token <token>] [--mode public|access-ready]
  stagehub expose cloudflare disable
  stagehub expose cloudflare status
  stagehub expose tailscale enable [--mode public|private] [--local-port <port>]
  stagehub expose tailscale disable
  stagehub expose tailscale status
USAGE
}

valid_port() {
  local value="$1"
  [[ "${value}" =~ ^[0-9]+$ ]] && [ "${value}" -ge 1 ] && [ "${value}" -le 65535 ]
}

stagehub_port() {
  local port=""
  if [ -f "${CONFIG_FILE}" ] && have_cmd python3; then
    port="$(python3 - <<PY
import json
try:
    with open("${CONFIG_FILE}", "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    print(int(cfg.get("port", 80)))
except Exception:
    print(80)
PY
)"
  fi
  if ! valid_port "${port:-}"; then
    port="80"
  fi
  printf '%s\n' "${port}"
}

ensure_stagehub_running() {
  if ! have_cmd systemctl; then
    die "systemctl is required."
  fi
  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    log "Starting ${SERVICE_NAME}..."
    systemctl start "${SERVICE_NAME}" || die "Could not start ${SERVICE_NAME}."
  fi
}

load_state() {
  if [ -f "${STATE_FILE}" ]; then
    # shellcheck disable=SC1090
    source "${STATE_FILE}"
  fi
}

save_state() {
  mkdir -p "${STATE_DIR}"
  umask 077
  {
    printf '# StageHub expose state\n'
    [ -n "${CF_MODE:-}" ] && printf 'CF_MODE=%q\n' "${CF_MODE}"
    [ -n "${TS_MODE:-}" ] && printf 'TS_MODE=%q\n' "${TS_MODE}"
    [ -n "${TS_LOCAL_PORT:-}" ] && printf 'TS_LOCAL_PORT=%q\n' "${TS_LOCAL_PORT}"
  } > "${STATE_FILE}"
  chmod 600 "${STATE_FILE}"
}

ensure_cloudflared_installed() {
  if have_cmd cloudflared; then
    return
  fi
  if ! have_cmd apt-get; then
    die "cloudflared missing and apt-get not available."
  fi

  log "Installing cloudflared..."
  apt-get update -y
  if apt-get install -y cloudflared; then
    return
  fi

  apt-get install -y ca-certificates curl gnupg
  install -d -m 0755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | gpg --dearmor --yes -o /usr/share/keyrings/cloudflare-main.gpg

  local codename="bookworm"
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    codename="${VERSION_CODENAME:-bookworm}"
  fi

  cat > /etc/apt/sources.list.d/cloudflared.list <<EOF
deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared ${codename} main
EOF

  apt-get update -y
  apt-get install -y cloudflared
  have_cmd cloudflared || die "cloudflared install failed."
}

cloudflare_enable() {
  local mode="$1"
  local token="$2"
  case "${mode}" in
    public|access-ready) ;;
    *) die "Invalid Cloudflare mode: ${mode}" ;;
  esac

  ensure_stagehub_running
  ensure_cloudflared_installed

  if [ -z "${token}" ]; then
    if [ -t 0 ] || [ -r /dev/tty ]; then
      read -r -s -p "Cloudflare tunnel token: " token < /dev/tty || true
      printf '\n'
    fi
  fi
  [ -n "${token}" ] || die "Cloudflare token is required."

  log "Installing and enabling Cloudflare tunnel service..."
  cloudflared service install "${token}" >/dev/null
  systemctl daemon-reload
  systemctl enable --now "${CF_SERVICE_NAME}"

  CF_MODE="${mode}"
  save_state

  log "Cloudflare enabled (mode: ${mode})."
  if [ "${mode}" = "access-ready" ]; then
    log "Next step: configure Cloudflare Access policies in the Cloudflare dashboard."
  fi
}

cloudflare_disable() {
  if have_cmd systemctl; then
    systemctl disable --now "${CF_SERVICE_NAME}" >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if have_cmd cloudflared; then
    cloudflared service uninstall >/dev/null 2>&1 || true
  fi

  unset CF_MODE
  save_state
  log "Cloudflare tunnel disabled."
}

cloudflare_status() {
  local state="inactive"
  if have_cmd systemctl && systemctl is-active --quiet "${CF_SERVICE_NAME}"; then
    state="active"
  fi
  printf 'Cloudflare: %s (mode: %s)\n' "${state}" "${CF_MODE:-public}"
}

ensure_tailscale_installed() {
  if have_cmd tailscale; then
    return
  fi
  if ! have_cmd curl; then
    die "tailscale missing and curl is not available."
  fi
  log "Installing Tailscale..."
  curl -fsSL https://tailscale.com/install.sh | sh
  have_cmd tailscale || die "Tailscale install failed."
}

ensure_tailscale_connected() {
  if ! tailscale status >/dev/null 2>&1; then
    die "Tailscale is not connected yet. Run: tailscale up"
  fi
}

tailscale_enable() {
  local mode="$1"
  local local_port="$2"
  case "${mode}" in
    public|private) ;;
    *) die "Invalid Tailscale mode: ${mode}" ;;
  esac
  valid_port "${local_port}" || die "Invalid local port: ${local_port}"

  ensure_stagehub_running
  ensure_tailscale_installed
  ensure_tailscale_connected

  tailscale funnel reset >/dev/null 2>&1 || true
  tailscale serve reset >/dev/null 2>&1 || true

  if [ "${mode}" = "public" ]; then
    tailscale funnel --bg "${local_port}"
  else
    tailscale serve --bg "${local_port}"
  fi

  TS_MODE="${mode}"
  TS_LOCAL_PORT="${local_port}"
  save_state

  log "Tailscale enabled (mode: ${mode}, local port: ${local_port})."
}

tailscale_disable() {
  if have_cmd tailscale; then
    tailscale funnel reset >/dev/null 2>&1 || true
    tailscale serve reset >/dev/null 2>&1 || true
  fi

  unset TS_MODE
  unset TS_LOCAL_PORT
  save_state
  log "Tailscale serve/funnel disabled."
}

tailscale_status() {
  if ! have_cmd tailscale; then
    printf 'Tailscale: not installed\n'
    return
  fi

  if tailscale status >/dev/null 2>&1; then
    printf 'Tailscale: connected (mode: %s, local port: %s)\n' "${TS_MODE:-unknown}" "${TS_LOCAL_PORT:-unknown}"
  else
    printf 'Tailscale: installed but not connected (run: tailscale up)\n'
    return
  fi

  if tailscale serve status >/dev/null 2>&1; then
    tailscale serve status | sed 's/^/  /'
  else
    printf '  No active serve/funnel config.\n'
  fi
}

status_all() {
  cloudflare_status
  tailscale_status
}

main() {
  require_root
  load_state

  local provider="${1:-}"
  case "${provider}" in
    ""|help|-h|--help)
      usage
      ;;
    status)
      status_all
      ;;
    cloudflare)
      local action="${2:-}"
      shift 2 || true
      case "${action}" in
        enable)
          local mode="public"
          local token=""
          while [ "$#" -gt 0 ]; do
            case "$1" in
              --mode)
                shift
                mode="${1:-}"
                ;;
              --token)
                shift
                token="${1:-}"
                ;;
              *)
                die "Unknown cloudflare option: $1"
                ;;
            esac
            shift || true
          done
          cloudflare_enable "${mode}" "${token}"
          ;;
        disable)
          cloudflare_disable
          ;;
        status)
          cloudflare_status
          ;;
        *)
          die "Unknown cloudflare action: ${action:-<none>}"
          ;;
      esac
      ;;
    tailscale)
      local action="${2:-}"
      shift 2 || true
      case "${action}" in
        enable)
          local mode="public"
          local local_port
          local_port="$(stagehub_port)"
          while [ "$#" -gt 0 ]; do
            case "$1" in
              --mode)
                shift
                mode="${1:-}"
                ;;
              --local-port)
                shift
                local_port="${1:-}"
                ;;
              *)
                die "Unknown tailscale option: $1"
                ;;
            esac
            shift || true
          done
          tailscale_enable "${mode}" "${local_port}"
          ;;
        disable)
          tailscale_disable
          ;;
        status)
          tailscale_status
          ;;
        *)
          die "Unknown tailscale action: ${action:-<none>}"
          ;;
      esac
      ;;
    *)
      die "Unknown expose target: ${provider}"
      ;;
  esac
}

main "$@"
