#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/stagehub"
CONFIG_FILE="${INSTALL_DIR}/config.json"
STATE_DIR="/etc/stagehub"
STATE_FILE="${STATE_DIR}/expose-state.env"
SERVICE_NAME="stagehub.service"

CF_SERVICE_NAME="cloudflared.service"
CF_QUICK_SERVICE_NAME="stagehub-cloudflared-quick.service"
CF_QUICK_SERVICE_FILE="/etc/systemd/system/${CF_QUICK_SERVICE_NAME}"
STAGEHUB_HTTPS_BACKEND_PORT="8443"
TAILSCALE_HTTPS_PORT="443"

COLOR_RESET=""
COLOR_BOLD=""
COLOR_CYAN=""
COLOR_GREEN=""
COLOR_RED=""
COLOR_BLUE=""
if [ -t 1 ]; then
  COLOR_RESET=$'\033[0m'
  COLOR_BOLD=$'\033[1m'
  COLOR_CYAN=$'\033[36m'
  COLOR_GREEN=$'\033[32m'
  COLOR_RED=$'\033[31m'
  COLOR_BLUE=$'\033[34m'
fi

log() {
  printf '%b[stagehub-expose]%b %s\n' "${COLOR_CYAN}" "${COLOR_RESET}" "$*"
}

die() {
  printf '%b[stagehub-expose] ERROR:%b %s\n' "${COLOR_RED}" "${COLOR_RESET}" "$*" >&2
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

is_menu_tty() {
  [ -t 1 ] && [ -r /dev/tty ]
}

menu_select() {
  local title="$1"
  local default_idx="$2"
  shift 2
  local -a options=("$@")
  local count="${#options[@]}"
  local idx="${default_idx}"
  local key=""
  local next=""
  local lines=0
  local n=0

  [ "${count}" -gt 0 ] || die "menu_select requires at least one option."
  if [ "${idx}" -lt 0 ] || [ "${idx}" -ge "${count}" ]; then
    idx=0
  fi

  if ! is_menu_tty; then
    printf '%s\n' "${title}"
    for n in "${!options[@]}"; do
      printf '  %d) %s\n' "$((n + 1))" "${options[$n]}"
    done
    while true; do
      key="$(ask_input "Select [1-${count}]")"
      if [[ "${key}" =~ ^[0-9]+$ ]] && [ "${key}" -ge 1 ] && [ "${key}" -le "${count}" ]; then
        printf '%s\n' "${key}"
        return
      fi
    done
  fi

  lines=$((count + 1))
  while true; do
    printf '%b%s%b\n' "${COLOR_BOLD}${COLOR_BLUE}" "${title}" "${COLOR_RESET}"
    for n in "${!options[@]}"; do
      if [ "${n}" -eq "${idx}" ]; then
        printf '  %b> %s%b\n' "${COLOR_BOLD}${COLOR_GREEN}" "${options[$n]}" "${COLOR_RESET}"
      else
        printf '    %s\n' "${options[$n]}"
      fi
    done

    IFS= read -rsn1 key < /dev/tty || true
    if [ "${key}" = $'\x1b' ]; then
      IFS= read -rsn1 -t 0.05 next < /dev/tty || true
      if [ "${next}" = "[" ]; then
        IFS= read -rsn1 -t 0.05 next < /dev/tty || true
        case "${next}" in
          A) idx=$(( (idx - 1 + count) % count )) ;;
          B) idx=$(( (idx + 1) % count )) ;;
        esac
      fi
    elif [ -z "${key}" ] || [ "${key}" = $'\n' ]; then
      printf '%s\n' "$((idx + 1))"
      return
    elif [[ "${key}" =~ ^[1-9]$ ]] && [ "${key}" -le "${count}" ]; then
      printf '%s\n' "${key}"
      return
    fi

    printf '\033[%dA\033[J' "${lines}"
  done
}

usage() {
  cat <<'USAGE'
Usage:
  stagehub expose
  stagehub expose status
  stagehub expose cloudflare
  stagehub expose cloudflare enable [--mode quick|public|access-ready] [--token <token>]
  stagehub expose cloudflare disable
  stagehub expose cloudflare status
  stagehub expose tailscale
  stagehub expose tailscale enable [--mode public|private] [--local-port <port>]
  stagehub expose tailscale disable
  stagehub expose tailscale status

Notes:
  - `stagehub expose` starts an interactive menu (no extra args needed).
  - Interactive menu supports arrow keys + Enter.
  - Cloudflare `quick` mode is one-click and gives a trycloudflare.com URL.
USAGE
}

ask_input() {
  local prompt="$1"
  local default="${2:-}"
  local out=""
  if [ -n "${default}" ]; then
    read -r -p "${prompt} [${default}]: " out < /dev/tty || true
    [ -n "${out}" ] || out="${default}"
  else
    read -r -p "${prompt}: " out < /dev/tty || true
  fi
  printf '%s\n' "${out}"
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
  if ! apt-get update -y; then
    if [ -f /etc/apt/sources.list.d/cloudflared.list ]; then
      log "Removing broken Cloudflare apt source and retrying apt update..."
      rm -f /etc/apt/sources.list.d/cloudflared.list || true
      apt-get update -y || true
    fi
  fi

  if apt-get install -y cloudflared >/dev/null 2>&1; then
    return
  fi

  apt-get install -y ca-certificates curl gnupg
  install -d -m 0755 /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | gpg --dearmor --yes -o /usr/share/keyrings/cloudflare-main.gpg

  local codename="bookworm"
  local repo_codename=""
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    codename="${VERSION_CODENAME:-bookworm}"
  fi

  case "${codename}" in
    bullseye|bookworm)
      repo_codename="${codename}"
      ;;
    *)
      # Cloudflare may lag behind Debian codenames (for example trixie), so fallback to bookworm.
      repo_codename="bookworm"
      ;;
  esac

  cat > /etc/apt/sources.list.d/cloudflared.list <<EOF
deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared ${repo_codename} main
EOF

  if apt-get update -y && apt-get install -y cloudflared; then
    have_cmd cloudflared || die "cloudflared install failed."
    return
  fi

  log "Apt install failed. Falling back to GitHub release package..."
  rm -f /etc/apt/sources.list.d/cloudflared.list || true
  apt-get update -y || true

  local arch=""
  local asset=""
  local tmp_deb=""
  if have_cmd dpkg; then
    arch="$(dpkg --print-architecture 2>/dev/null || true)"
  fi
  if [ -z "${arch}" ]; then
    arch="$(uname -m)"
  fi

  case "${arch}" in
    amd64|x86_64)
      asset="cloudflared-linux-amd64.deb"
      ;;
    arm64|aarch64)
      asset="cloudflared-linux-arm64.deb"
      ;;
    armhf|armv7l)
      asset="cloudflared-linux-armhf.deb"
      ;;
    arm|armel)
      asset="cloudflared-linux-arm.deb"
      ;;
    i386|i686)
      asset="cloudflared-linux-386.deb"
      ;;
    *)
      die "Unsupported architecture for cloudflared auto-install: ${arch}"
      ;;
  esac

  tmp_deb="$(mktemp /tmp/cloudflared.XXXXXX.deb)"
  curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/${asset}" -o "${tmp_deb}"
  dpkg -i "${tmp_deb}" >/dev/null || apt-get -f install -y
  rm -f "${tmp_deb}" || true

  have_cmd cloudflared || die "cloudflared install failed."
}

write_cloudflare_quick_service() {
  local cloudflared_bin
  cloudflared_bin="$(command -v cloudflared)"
  cat > "${CF_QUICK_SERVICE_FILE}" <<EOF
[Unit]
Description=StageHub Cloudflare Quick Tunnel
After=network-online.target ${SERVICE_NAME}
Wants=network-online.target

[Service]
Type=simple
ExecStart=${cloudflared_bin} tunnel --no-autoupdate --url https://127.0.0.1:${STAGEHUB_HTTPS_BACKEND_PORT} --no-tls-verify
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}

cloudflare_quick_url() {
  if ! have_cmd journalctl; then
    return
  fi
  journalctl -u "${CF_QUICK_SERVICE_NAME}" -n 120 --no-pager 2>/dev/null \
    | sed -n 's#.*\(https://[a-z0-9-]\+\.trycloudflare\.com\).*#\1#p' \
    | tail -n1
}

cloudflare_enable_quick() {
  ensure_stagehub_running
  ensure_cloudflared_installed

  if have_cmd systemctl; then
    systemctl disable --now "${CF_SERVICE_NAME}" >/dev/null 2>&1 || true
  fi

  write_cloudflare_quick_service
  systemctl daemon-reload
  systemctl enable --now "${CF_QUICK_SERVICE_NAME}"

  CF_MODE="quick"
  save_state

  sleep 2
  local url=""
  url="$(cloudflare_quick_url || true)"
  log "Cloudflare quick tunnel enabled."
  if [ -n "${url}" ]; then
    log "Public URL: ${url}"
  else
    log "Quick URL not parsed yet. Check logs: journalctl -u ${CF_QUICK_SERVICE_NAME} -n 100 --no-pager"
  fi
}

cloudflare_enable_token() {
  local mode="$1"
  local token="$2"
  case "${mode}" in
    public|access-ready) ;;
    *) die "Invalid Cloudflare mode: ${mode}" ;;
  esac

  ensure_stagehub_running
  ensure_cloudflared_installed

  if [ -z "${token}" ]; then
    read -r -s -p "Cloudflare tunnel token: " token < /dev/tty || true
    printf '\n'
  fi
  [ -n "${token}" ] || die "Cloudflare token is required."

  systemctl disable --now "${CF_QUICK_SERVICE_NAME}" >/dev/null 2>&1 || true
  rm -f "${CF_QUICK_SERVICE_FILE}" || true

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

cloudflare_enable() {
  local mode="$1"
  local token="$2"
  case "${mode}" in
    quick)
      cloudflare_enable_quick
      ;;
    public|access-ready)
      cloudflare_enable_token "${mode}" "${token}"
      ;;
    *)
      die "Invalid Cloudflare mode: ${mode}"
      ;;
  esac
}

cloudflare_disable() {
  if have_cmd systemctl; then
    systemctl disable --now "${CF_SERVICE_NAME}" >/dev/null 2>&1 || true
    systemctl disable --now "${CF_QUICK_SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
  rm -f "${CF_QUICK_SERVICE_FILE}" || true

  if have_cmd cloudflared; then
    cloudflared service uninstall >/dev/null 2>&1 || true
  fi

  if have_cmd systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi

  unset CF_MODE
  save_state
  log "Cloudflare tunnel disabled."
}

cloudflare_status() {
  local state="inactive"
  local detail="none"
  if have_cmd systemctl && systemctl is-active --quiet "${CF_SERVICE_NAME}"; then
    state="active"
    detail="token-service"
  fi
  if have_cmd systemctl && systemctl is-active --quiet "${CF_QUICK_SERVICE_NAME}"; then
    state="active"
    detail="quick-tunnel"
  fi
  printf 'Cloudflare: %s (mode: %s, detail: %s)\n' "${state}" "${CF_MODE:-none}" "${detail}"
  if [ "${detail}" = "quick-tunnel" ]; then
    local url=""
    url="$(cloudflare_quick_url || true)"
    if [ -n "${url}" ]; then
      printf '  URL: %s\n' "${url}"
    fi
  fi
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

tailscale_target_from_port() {
  local local_port="$1"
  if [ "${local_port}" = "${STAGEHUB_HTTPS_BACKEND_PORT}" ]; then
    printf 'https+insecure://127.0.0.1:%s\n' "${local_port}"
  else
    printf 'http://127.0.0.1:%s\n' "${local_port}"
  fi
}

tailscale_clear_routes() {
  local https_port="${1}"

  # Explicit off commands first (matches the command Tailscale prints to users).
  tailscale funnel --yes --https="${https_port}" off >/dev/null 2>&1 || true
  tailscale serve --yes --https="${https_port}" off >/dev/null 2>&1 || true

  # Older CLIs may use positional syntax.
  tailscale funnel --yes "${https_port}" off >/dev/null 2>&1 || true
  tailscale serve --yes "${https_port}" off >/dev/null 2>&1 || true

  # Safety net for any leftover mappings.
  tailscale funnel reset --yes >/dev/null 2>&1 \
    || tailscale funnel --yes reset >/dev/null 2>&1 \
    || tailscale funnel reset >/dev/null 2>&1 \
    || true
  tailscale serve reset --yes >/dev/null 2>&1 \
    || tailscale serve --yes reset >/dev/null 2>&1 \
    || tailscale serve reset >/dev/null 2>&1 \
    || true
}

tailscale_enable() {
  local mode="$1"
  local local_port="$2"
  local target
  local https_port="${TAILSCALE_HTTPS_PORT}"
  case "${mode}" in
    public|private) ;;
    *) die "Invalid Tailscale mode: ${mode}" ;;
  esac
  valid_port "${local_port}" || die "Invalid local port: ${local_port}"

  ensure_stagehub_running
  ensure_tailscale_installed
  ensure_tailscale_connected

  target="$(tailscale_target_from_port "${local_port}")"

  tailscale_clear_routes "${https_port}"

  if [ "${mode}" = "public" ]; then
    # Newer CLIs use "tailscale funnel <target>"; older CLIs may still use serve+funnel on.
    tailscale funnel --yes --bg --https="${https_port}" "${target}" >/dev/null 2>&1 \
      || tailscale funnel --yes --bg "${target}" >/dev/null 2>&1 \
      || tailscale serve --yes --bg --https="${https_port}" "${target}" >/dev/null 2>&1 \
      || tailscale serve --yes --bg "${target}" >/dev/null 2>&1 \
      || tailscale funnel --yes --https="${https_port}" on >/dev/null 2>&1 \
      || tailscale funnel --yes "${https_port}" on >/dev/null 2>&1 \
      || tailscale funnel --yes on >/dev/null 2>&1 \
      || tailscale funnel --yes --bg --https="${https_port}" on >/dev/null 2>&1 \
      || tailscale funnel --yes --bg "${https_port}" on >/dev/null 2>&1 \
      || tailscale funnel --yes --bg on >/dev/null 2>&1 \
      || die "tailscale funnel enable failed."
  else
    tailscale serve --yes --bg --https="${https_port}" "${target}" >/dev/null 2>&1 \
      || tailscale serve --yes --bg "${target}" >/dev/null 2>&1 \
      || tailscale serve --yes --https="${https_port}" "${target}" >/dev/null 2>&1 \
      || tailscale serve --yes "${target}" >/dev/null 2>&1 \
      || die "tailscale serve enable failed."
  fi

  TS_MODE="${mode}"
  TS_LOCAL_PORT="${local_port}"
  save_state

  log "Tailscale enabled (mode: ${mode}, target: ${target})."
  if [ "${mode}" = "public" ]; then
    log "Public endpoint uses HTTPS port ${https_port}. If link fails, verify Funnel policy and run: tailscale funnel status"
  fi
}

tailscale_disable() {
  if have_cmd tailscale; then
    tailscale_clear_routes "${TAILSCALE_HTTPS_PORT}"
    if valid_port "${TS_LOCAL_PORT:-}" && [ "${TS_LOCAL_PORT}" != "${TAILSCALE_HTTPS_PORT}" ]; then
      tailscale_clear_routes "${TS_LOCAL_PORT}"
    fi
  fi

  unset TS_MODE
  unset TS_LOCAL_PORT
  save_state
  log "Tailscale serve/funnel disabled (including funnel --https=${TAILSCALE_HTTPS_PORT} off)."
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

interactive_cloudflare_enable() {
  local choice=""
  local token=""
  printf '\n'
  choice="$(menu_select "Cloudflare enable mode (Use arrows + Enter)" 0 \
    "Quick one-click public link (trycloudflare)" \
    "Public custom-domain tunnel (token required)" \
    "Access-ready custom-domain tunnel (token required)")"
  case "${choice}" in
    1)
      cloudflare_enable "quick" ""
      ;;
    2)
      token="$(ask_input 'Cloudflare tunnel token')"
      cloudflare_enable "public" "${token}"
      ;;
    3)
      token="$(ask_input 'Cloudflare tunnel token')"
      cloudflare_enable "access-ready" "${token}"
      ;;
    *)
      die "Invalid selection."
      ;;
  esac
}

interactive_cloudflare_menu() {
  local choice=""
  printf '\n'
  choice="$(menu_select "Cloudflare menu (Use arrows + Enter)" 0 \
    "Enable" \
    "Disable" \
    "Status" \
    "Back")"
  case "${choice}" in
    1) interactive_cloudflare_enable ;;
    2) cloudflare_disable ;;
    3) cloudflare_status ;;
    4) return ;;
    *) die "Invalid selection." ;;
  esac
}

interactive_tailscale_enable() {
  local choice=""
  local mode="public"
  local local_port="${STAGEHUB_HTTPS_BACKEND_PORT}"

  printf '\n'
  choice="$(menu_select "Tailscale enable mode (Use arrows + Enter)" 0 \
    "Public internet link (Funnel)" \
    "Private tailnet-only link (Serve)")"
  case "${choice}" in
    1) mode="public" ;;
    2) mode="private" ;;
    *) die "Invalid selection." ;;
  esac

  local_port="$(ask_input 'Local backend port (recommended 8443)' "${STAGEHUB_HTTPS_BACKEND_PORT}")"
  valid_port "${local_port}" || die "Invalid local backend port: ${local_port}"
  tailscale_enable "${mode}" "${local_port}"
}

interactive_tailscale_menu() {
  local choice=""
  printf '\n'
  choice="$(menu_select "Tailscale menu (Use arrows + Enter)" 0 \
    "Enable" \
    "Disable" \
    "Status" \
    "Back")"
  case "${choice}" in
    1) interactive_tailscale_enable ;;
    2) tailscale_disable ;;
    3) tailscale_status ;;
    4) return ;;
    *) die "Invalid selection." ;;
  esac
}

interactive_main_menu() {
  local choice=""
  while true; do
    printf '\n'
    choice="$(menu_select "StageHub Expose Menu (Use arrows + Enter)" 0 \
      "Status" \
      "Cloudflare" \
      "Tailscale" \
      "Exit")"
    case "${choice}" in
      1) status_all ;;
      2) interactive_cloudflare_menu ;;
      3) interactive_tailscale_menu ;;
      4) return ;;
      *) die "Invalid selection." ;;
    esac
  done
}

main() {
  require_root
  load_state

  local provider="${1:-}"
  case "${provider}" in
    "" )
      interactive_main_menu
      ;;
    help|-h|--help)
      usage
      ;;
    status)
      status_all
      ;;
    cloudflare)
      local action="${2:-}"
      shift 2 || true
      case "${action}" in
        "" )
          interactive_cloudflare_menu
          ;;
        enable)
          local mode="quick"
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
        "")
          interactive_tailscale_menu
          ;;
        enable)
          local mode="public"
          local local_port="${STAGEHUB_HTTPS_BACKEND_PORT}"
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
