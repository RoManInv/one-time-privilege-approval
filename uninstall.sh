#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="privilege-approval"
GROUP_NAME="privilege-requesters"

BIN_REQUEST="/usr/local/bin/request-privilege"
BIN_RUN="/usr/local/bin/run-approved"
LIBEXEC_DIR="/usr/local/libexec/${PROJECT_NAME}"
ETC_DIR="/etc/${PROJECT_NAME}"
STATE_DIR="/var/lib/${PROJECT_NAME}"
LOG_DIR="/var/log/${PROJECT_NAME}"
SUDO_IO_DIR="/var/log/sudo-io/${PROJECT_NAME}"
SUDOERS_TARGET="/etc/sudoers.d/privilege-approval-sudoer"
SYSTEMD_DIR="/etc/systemd/system"

ASSUME_YES="no"

for arg in "$@"; do
    case "${arg}" in
        -y|--yes)
            ASSUME_YES="yes"
            ;;
        *)
            echo "ERROR: unknown argument: ${arg}" >&2
            echo "Usage: sudo scripts/uninstall.sh [--yes]" >&2
            exit 1
            ;;
    esac
done

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "ERROR: uninstall.sh must be run as root, e.g. sudo uninstall.sh --yes" >&2
        exit 1
    fi
}

confirm() {
    if [[ "${ASSUME_YES}" == "yes" ]]; then
        return
    fi

    echo "This will permanently remove:"
    echo "  ${BIN_REQUEST}"
    echo "  ${BIN_RUN}"
    echo "  ${LIBEXEC_DIR}"
    echo "  ${ETC_DIR}"
    echo "  ${STATE_DIR}"
    echo "  ${LOG_DIR}"
    echo "  ${SUDO_IO_DIR}"
    echo "  ${SUDOERS_TARGET}"
    echo "  ${SYSTEMD_DIR}/privilege-approval-*"
    echo
    read -r -p "Type REMOVE to continue: " answer
    if [[ "${answer}" != "REMOVE" ]]; then
        echo "Aborted."
        exit 1
    fi
}

stop_systemd_units() {
    local units=(
        privilege-approval-check.path
        privilege-approval-check.timer
        privilege-approval-check.service
        privilege-approval-cleanup.timer
        privilege-approval-cleanup.service
    )

    for unit in "${units[@]}"; do
        systemctl disable --now "${unit}" >/dev/null 2>&1 || true
    done
}

remove_files() {
    rm -f "${BIN_REQUEST}"
    rm -f "${BIN_RUN}"

    rm -rf "${LIBEXEC_DIR}"
    rm -rf "${ETC_DIR}"
    rm -rf "${STATE_DIR}"
    rm -rf "${LOG_DIR}"
    rm -rf "${SUDO_IO_DIR}"

    rm -f "${SUDOERS_TARGET}"

    rm -f "${SYSTEMD_DIR}/privilege-approval-check.path"
    rm -f "${SYSTEMD_DIR}/privilege-approval-check.timer"
    rm -f "${SYSTEMD_DIR}/privilege-approval-check.service"
    rm -f "${SYSTEMD_DIR}/privilege-approval-cleanup.timer"
    rm -f "${SYSTEMD_DIR}/privilege-approval-cleanup.service"
}

remove_group() {
    if getent group "${GROUP_NAME}" >/dev/null; then
        groupdel "${GROUP_NAME}" || {
            echo "WARNING: failed to remove group ${GROUP_NAME}. It may be a primary group or in use." >&2
        }
    fi
}

reload_systemd() {
    systemctl daemon-reload || true
    systemctl reset-failed >/dev/null 2>&1 || true
}

main() {
    need_root
    confirm
    stop_systemd_units
    remove_files
    remove_group
    reload_systemd

    echo "Uninstalled ${PROJECT_NAME}. No project-owned files should remain."
}

main "$@"