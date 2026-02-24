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
  printf '%b[stagehub-uninstall]%b %s\n' "${COLOR_CYAN}" "${COLOR_RESET}" "$*"
}

die() {
  printf '%b[stagehub-uninstall] ERROR:%b %s\n' "${COLOR_RED}" "${COLOR_RESET}" "$*" >&2
  exit 1
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
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
      read -r -p "Select [1-${count}]: " key < /dev/tty || true
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

Interactive prompts support arrow keys + Enter.
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
  local choice=""
  local suffix="[y/N]"

  if is_menu_tty; then
    if [ "${default}" = "Y" ]; then
      choice="$(menu_select "${prompt}" 0 "Yes" "No")"
    else
      choice="$(menu_select "${prompt}" 1 "Yes" "No")"
    fi
    [ "${choice}" = "1" ]
    return
  fi

  if [ "${default}" = "Y" ]; then
    suffix="[Y/n]"
  fi
  read -r -p "${prompt} ${suffix}: " reply < /dev/tty || true
  if [ -z "${reply}" ]; then
    reply="${default}"
  fi
  case "${reply}" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
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
