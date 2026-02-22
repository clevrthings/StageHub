#!/usr/bin/env bash
set -euo pipefail

# StageChat Raspberry Pi installer
# Run with:
#   curl -fsSL https://raw.githubusercontent.com/clevrthings/StageChat/main/install.sh | sudo bash

REPO_OWNER="clevrthings"
REPO_NAME="StageChat"
BRANCH="main"

INSTALL_DIR="/opt/stagechat"
SERVICE_NAME="stagechat"
SYSTEMD_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"
CLI_BIN="/usr/local/bin/stagechat"
DEFAULT_SERVICE_USER="stagechat"


log() {
  printf '[stagechat-install] %s\n' "$*"
}

die() {
  printf '[stagechat-install] ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "Run this installer as root. Example: curl -fsSL https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}/install.sh | sudo bash"
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

coerce_port() {
  local value="$1"
  if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 65535 ]; then
    printf '%s\n' "$value"
  else
    printf '5001\n'
  fi
}

prompt_default() {
  local label="$1"
  local default="$2"
  local reply
  read -r -p "${label} [${default}]: " reply || true
  if [ -n "${reply}" ]; then
    printf '%s\n' "${reply}"
  else
    printf '%s\n' "${default}"
  fi
}

ensure_packages() {
  if ! have_cmd apt-get; then
    die "This installer currently supports apt-based systems (Raspberry Pi OS / Debian)."
  fi
  log "Installing system dependencies (git, curl, python3, venv)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y git curl ca-certificates python3 python3-venv python3-pip
}

clone_repo() {
  local url="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
  log "Cloning ${url} (${BRANCH}) into ${INSTALL_DIR}"
  git clone --branch "${BRANCH}" --depth 1 "${url}" "${INSTALL_DIR}"
}

update_repo() {
  log "Updating existing repository in ${INSTALL_DIR}"
  git -C "${INSTALL_DIR}" fetch origin "${BRANCH}"
  git -C "${INSTALL_DIR}" checkout -B "${BRANCH}" "origin/${BRANCH}"
  git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}"
}

choose_install_mode() {
  if [ -d "${INSTALL_DIR}/.git" ]; then
    log "Existing StageChat installation detected at ${INSTALL_DIR}"
    while true; do
      cat <<'EOF'
Choose install mode:
  1) Update existing installation (keep data/config)
  2) Clean reinstall (delete installation folder)
  3) Cancel
EOF
      read -r -p "Select [1/2/3]: " mode || true
      case "${mode:-}" in
        1)
          update_repo
          return
          ;;
        2)
          read -r -p "This removes ${INSTALL_DIR}. Continue? [y/N]: " confirm || true
          case "${confirm:-n}" in
            y|Y|yes|YES)
              rm -rf "${INSTALL_DIR}"
              clone_repo
              return
              ;;
            *)
              ;;
          esac
          ;;
        3)
          die "Cancelled by user."
          ;;
        *)
          ;;
      esac
    done
  fi

  if [ -d "${INSTALL_DIR}" ] && [ ! -d "${INSTALL_DIR}/.git" ]; then
    log "Directory ${INSTALL_DIR} exists but is not a git checkout."
    read -r -p "Delete and reinstall into ${INSTALL_DIR}? [y/N]: " confirm || true
    case "${confirm:-n}" in
      y|Y|yes|YES)
        rm -rf "${INSTALL_DIR}"
        ;;
      *)
        die "Cancelled by user."
        ;;
    esac
  fi

  if [ ! -d "${INSTALL_DIR}" ]; then
    clone_repo
  fi
}

resolve_nologin_shell() {
  if [ -x /usr/sbin/nologin ]; then
    printf '/usr/sbin/nologin\n'
  elif [ -x /sbin/nologin ]; then
    printf '/sbin/nologin\n'
  elif have_cmd nologin; then
    command -v nologin
  else
    printf '/bin/false\n'
  fi
}

choose_service_user() {
  local candidate
  while true; do
    candidate="$(prompt_default "Linux user for StageChat service" "${DEFAULT_SERVICE_USER}")"
    if id -u "${candidate}" >/dev/null 2>&1; then
      printf '%s\n' "${candidate}"
      return
    fi
    read -r -p "User '${candidate}' does not exist. Create system user? [Y/n]: " create_ans || true
    case "${create_ans:-Y}" in
      n|N|no|NO)
        ;;
      *)
        useradd --system --create-home --home-dir "/var/lib/${SERVICE_NAME}" --shell "$(resolve_nologin_shell)" "${candidate}"
        printf '%s\n' "${candidate}"
        return
        ;;
    esac
  done
}

read_existing_config_defaults() {
  local file="$1"
  python3 - "$file" <<'PY'
import json
import sys

path = sys.argv[1]
defaults = {
    "active_project": "default",
    "port": 5001,
    "username_case_sensitive": False,
}

try:
    with open(path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
except Exception:
    loaded = {}

active = str(loaded.get("active_project", defaults["active_project"]) or "default")
try:
    port = int(loaded.get("port", defaults["port"]))
except Exception:
    port = defaults["port"]
if not (1 <= port <= 65535):
    port = defaults["port"]

case_sensitive = bool(loaded.get("username_case_sensitive", defaults["username_case_sensitive"]))
print(active)
print(port)
print("true" if case_sensitive else "false")
PY
}

write_config_file() {
  local file="$1"
  local active_project="$2"
  local port="$3"
  local case_sensitive="$4"
  python3 - "$file" "$active_project" "$port" "$case_sensitive" <<'PY'
import json
import sys

path, active, port_raw, case_raw = sys.argv[1:5]
try:
    port = int(port_raw)
except Exception:
    port = 5001
if not (1 <= port <= 65535):
    port = 5001
case_sensitive = str(case_raw).lower() == "true"

payload = {
    "active_project": active or "default",
    "port": port,
    "username_case_sensitive": case_sensitive,
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
PY
}

configure_main_config() {
  local config_file="${INSTALL_DIR}/config.json"
  local defaults_file="$1"
  local default_project
  local default_port
  local default_case
  local input_port
  local port
  local case_prompt
  local case_input
  local case_value

  mapfile -t cfg < <(read_existing_config_defaults "${defaults_file}")
  default_project="${cfg[0]:-default}"
  default_port="${cfg[1]:-5001}"
  default_case="${cfg[2]:-false}"

  while true; do
    input_port="$(prompt_default "Port for StageChat" "${default_port}")"
    port="$(coerce_port "${input_port}")"
    if [ "${port}" = "${input_port}" ]; then
      break
    fi
    log "Invalid port '${input_port}'. Please choose a value between 1 and 65535."
  done

  if [ "${default_case}" = "true" ]; then
    case_prompt="Y/n"
  else
    case_prompt="y/N"
  fi
  read -r -p "Username case-sensitive mode? [${case_prompt}]: " case_input || true
  case "${case_input:-}" in
    y|Y|yes|YES)
      case_value="true"
      ;;
    n|N|no|NO)
      case_value="false"
      ;;
    *)
      case_value="${default_case}"
      ;;
  esac

  write_config_file "${config_file}" "${default_project}" "${port}" "${case_value}"
}

setup_python_env() {
  log "Creating virtual environment and installing Python dependencies..."
  python3 -m venv "${INSTALL_DIR}/.venv"
  "${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip
  "${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
}

write_systemd_service() {
  local service_user="$1"
  cat > "${SYSTEMD_UNIT}" <<EOF
[Unit]
Description=StageChat server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${service_user}
Group=${service_user}
WorkingDirectory=${INSTALL_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/app.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}

write_cli_wrapper() {
  cat > "${CLI_BIN}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="stagechat.service"

run_systemctl() {
  if [ "$(id -u)" -eq 0 ]; then
    exec systemctl "$@" "${SERVICE_NAME}"
  else
    exec sudo systemctl "$@" "${SERVICE_NAME}"
  fi
}

cmd="${1:-}"
case "${cmd}" in
  start)
    run_systemctl start
    ;;
  stop)
    run_systemctl stop
    ;;
  restart)
    run_systemctl restart
    ;;
  status)
    run_systemctl status
    ;;
  ""|help|-h|--help)
    cat <<'USAGE'
Usage: stagechat <command>

Commands:
  start      Start StageChat service
  stop       Stop StageChat service
  restart    Restart StageChat service
  status     Show StageChat service status
USAGE
    ;;
  *)
    echo "Unknown command: ${cmd}" >&2
    echo "Run 'stagechat help' for usage." >&2
    exit 1
    ;;
esac
EOF
  chmod 755 "${CLI_BIN}"
}

enable_and_start_service() {
  log "Enabling and starting ${SERVICE_NAME}.service..."
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}.service"
  systemctl restart "${SERVICE_NAME}.service"
  sleep 1
  if ! systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
    die "Service failed to start. See logs: journalctl -u ${SERVICE_NAME}.service -n 100 --no-pager"
  fi
}

main() {
  require_root
  have_cmd systemctl || die "systemctl not found. This installer requires systemd."
  ensure_packages

  local backup_config
  backup_config="$(mktemp)"
  trap 'rm -f "${backup_config}"' EXIT

  if [ -f "${INSTALL_DIR}/config.json" ]; then
    cp "${INSTALL_DIR}/config.json" "${backup_config}"
  else
    write_config_file "${backup_config}" "default" "5001" "false"
  fi

  choose_install_mode

  local service_user
  service_user="$(choose_service_user)"

  chown -R "${service_user}:${service_user}" "${INSTALL_DIR}"

  setup_python_env
  configure_main_config "${backup_config}"

  chown -R "${service_user}:${service_user}" "${INSTALL_DIR}"

  write_systemd_service "${service_user}"
  write_cli_wrapper
  enable_and_start_service

  local configured_port
  configured_port="$(python3 - <<PY
import json
cfg = json.load(open("${INSTALL_DIR}/config.json", "r", encoding="utf-8"))
print(int(cfg.get("port", 5001)))
PY
)"
  local host_ip
  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -z "${host_ip}" ]; then
    host_ip="localhost"
  fi

  log "Installation complete."
  log "Service: ${SERVICE_NAME}.service (running + enabled)"
  log "CLI commands: stagechat start | stagechat stop | stagechat restart"
  log "Open in browser:"
  log "  http://${host_ip}:${configured_port}  (auto-redirect to HTTPS)"
  log "  https://${host_ip}:${configured_port}"
}

main "$@"
