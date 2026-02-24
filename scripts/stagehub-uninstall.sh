#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="stagehub.service"
SYSTEMD_UNIT="/etc/systemd/system/${SERVICE_NAME}"
CLI_BIN="/usr/local/bin/stagehub"
INSTALL_DIR="/opt/stagehub"
SERVICE_USER="stagehub"
EXPOSE_SCRIPT="${INSTALL_DIR}/scripts/stagehub-expose.sh"

ASSUME_YES=0
DATA_MODE=""
EXPOSE_MODE=""
REMOVE_EXPOSE_PACKAGES=0
BACKUP_DIR=""

log() {
  printf '[stagehub-uninstall] %s\n' "$*"
}

die() {
  printf '[stagehub-uninstall] ERROR: %s\n' "$*" >&2
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
  stagehub uninstall [--yes] [--purge-data|--keep-data] [--remove-expose|--keep-expose] [--remove-expose-packages]

Options:
  --yes                      Non-interactive mode.
  --purge-data               Delete StageHub data and config.
  --keep-data                Keep data by moving projects + config to /var/backups/stagehub-<timestamp>/.
  --remove-expose            Disable Cloudflare/Tailscale exposure.
  --keep-expose              Leave Cloudflare/Tailscale as-is.
  --remove-expose-packages   Also uninstall cloudflared/tailscale packages (implies --remove-expose).
USAGE
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --yes)
        ASSUME_YES=1
        ;;
      --purge-data)
        [ "${DATA_MODE}" != "keep" ] || die "Choose either --purge-data or --keep-data."
        DATA_MODE="purge"
        ;;
      --keep-data)
        [ "${DATA_MODE}" != "purge" ] || die "Choose either --purge-data or --keep-data."
        DATA_MODE="keep"
        ;;
      --remove-expose)
        [ "${EXPOSE_MODE}" != "keep" ] || die "Choose either --remove-expose or --keep-expose."
        EXPOSE_MODE="remove"
        ;;
      --keep-expose)
        [ "${EXPOSE_MODE}" != "remove" ] || die "Choose either --remove-expose or --keep-expose."
        [ "${REMOVE_EXPOSE_PACKAGES}" -eq 0 ] || die "--keep-expose conflicts with --remove-expose-packages."
        EXPOSE_MODE="keep"
        ;;
      --remove-expose-packages)
        [ "${EXPOSE_MODE}" != "keep" ] || die "--remove-expose-packages conflicts with --keep-expose."
        EXPOSE_MODE="remove"
        REMOVE_EXPOSE_PACKAGES=1
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
    shift
  done
}

ask_yes_no() {
  local prompt="$1"
  local default="${2:-N}"
  local reply=""
  local suffix="[y/N]"
  if [ "${default}" = "Y" ]; then
    suffix="[Y/n]"
  fi
  read -r -p "${prompt} ${suffix}: " reply < /dev/tty || true
  if [ -z "${reply}" ]; then
    reply="${default}"
  fi
  case "${reply}" in
    y|Y|yes|YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

resolve_modes() {
  if [ "${ASSUME_YES}" -eq 1 ]; then
    if [ -z "${DATA_MODE}" ]; then
      DATA_MODE="keep"
    fi
    if [ -z "${EXPOSE_MODE}" ]; then
      EXPOSE_MODE="keep"
    fi
    return
  fi

  if [ -z "${DATA_MODE}" ]; then
    if ask_yes_no "Keep StageHub data (projects + config) as backup?" "Y"; then
      DATA_MODE="keep"
    else
      DATA_MODE="purge"
    fi
  fi

  if [ -z "${EXPOSE_MODE}" ]; then
    if ask_yes_no "Disable Cloudflare/Tailscale exposure during uninstall?" "Y"; then
      EXPOSE_MODE="remove"
    else
      EXPOSE_MODE="keep"
    fi
  fi

  if [ "${EXPOSE_MODE}" = "remove" ] && [ "${REMOVE_EXPOSE_PACKAGES}" -eq 0 ]; then
    if ask_yes_no "Also remove cloudflared/tailscale packages?" "N"; then
      REMOVE_EXPOSE_PACKAGES=1
    fi
  fi
}

confirm_destructive_action() {
  if [ "${ASSUME_YES}" -eq 1 ]; then
    return
  fi
  if ask_yes_no "Proceed with uninstall now?" "N"; then
    return
  fi
  die "Cancelled."
}

cleanup_exposure() {
  if [ "${EXPOSE_MODE}" != "remove" ]; then
    log "Leaving external exposure tooling untouched."
    return
  fi

  if [ -x "${EXPOSE_SCRIPT}" ]; then
    log "Disabling Cloudflare and Tailscale exposure..."
    bash "${EXPOSE_SCRIPT}" cloudflare disable || true
    bash "${EXPOSE_SCRIPT}" tailscale disable || true
  else
    log "Expose script not found; skipping staged disable."
  fi

  if [ "${REMOVE_EXPOSE_PACKAGES}" -eq 1 ] && have_cmd apt-get; then
    log "Removing exposure packages (best effort)..."
    apt-get remove -y cloudflared tailscale tailscale-archive-keyring >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    rm -f /etc/apt/sources.list.d/cloudflared.list /etc/apt/sources.list.d/tailscale.list || true
    rm -f /usr/share/keyrings/cloudflare-main.gpg /usr/share/keyrings/tailscale-archive-keyring.gpg || true
    apt-get update -y >/dev/null 2>&1 || true
  fi
}

stop_and_remove_service() {
  if have_cmd systemctl; then
    systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
  rm -f "${SYSTEMD_UNIT}" || true
  if have_cmd systemctl; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "${SERVICE_NAME}" >/dev/null 2>&1 || true
  fi
}

backup_data_if_needed() {
  if [ "${DATA_MODE}" != "keep" ]; then
    return
  fi

  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  BACKUP_DIR="/var/backups/stagehub-${ts}"
  mkdir -p "${BACKUP_DIR}"

  if [ -d "${INSTALL_DIR}/projects" ]; then
    mv "${INSTALL_DIR}/projects" "${BACKUP_DIR}/projects"
  fi
  if [ -f "${INSTALL_DIR}/config.json" ]; then
    mv "${INSTALL_DIR}/config.json" "${BACKUP_DIR}/config.json"
  fi
}

remove_installation_files() {
  rm -f "${CLI_BIN}" || true
  rm -rf "${INSTALL_DIR}" || true
}

remove_service_user_if_needed() {
  if [ "${DATA_MODE}" = "keep" ]; then
    return
  fi
  if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    userdel "${SERVICE_USER}" >/dev/null 2>&1 || true
  fi
}

print_summary() {
  log "Uninstall complete."
  log "Data mode: ${DATA_MODE}"
  log "Expose mode: ${EXPOSE_MODE}"
  if [ "${EXPOSE_MODE}" = "remove" ]; then
    if [ "${REMOVE_EXPOSE_PACKAGES}" -eq 1 ]; then
      log "Expose package cleanup: remove packages"
    else
      log "Expose package cleanup: disable/reset only"
    fi
  fi
  if [ "${DATA_MODE}" = "keep" ]; then
    log "Data backup location: ${BACKUP_DIR}"
    log "Restore by copying config.json + projects back into ${INSTALL_DIR} after reinstall."
  fi
}

main() {
  require_root
  parse_args "$@"
  resolve_modes
  confirm_destructive_action
  cleanup_exposure
  stop_and_remove_service
  backup_data_if_needed
  remove_installation_files
  remove_service_user_if_needed
  print_summary
}

main "$@"
