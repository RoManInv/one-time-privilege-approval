#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="privilege-approval"
GROUP_NAME="privilege-requesters"

BIN_DIR="/usr/local/bin"
LIBEXEC_DIR="/usr/local/libexec/${PROJECT_NAME}"
ETC_DIR="/etc/${PROJECT_NAME}"
USERS_DIR="${ETC_DIR}/users.d"
STATE_DIR="/var/lib/${PROJECT_NAME}"
LOG_DIR="/var/log/${PROJECT_NAME}"
SUDO_IO_DIR="/var/log/sudo-io/${PROJECT_NAME}"
SYSTEMD_DIR="/etc/systemd/system"
SUDOERS_TARGET="/etc/sudoers.d/privilege-approval-sudoer"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "${SCRIPT_DIR}/../libexec" || -d "${SCRIPT_DIR}/../bin" ]]; then
    PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
else
    PROJECT_ROOT="${SCRIPT_DIR}"
fi

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "ERROR: install.sh must be run as root, e.g. sudo install.sh" >&2
        exit 1
    fi
}

arrange_flat_layout_if_needed() {
    cd "${PROJECT_ROOT}"

    mkdir -p bin libexec/privilege-approval systemd sudoers scripts

    for f in request-privilege run-approved; do
        if [[ -f "${PROJECT_ROOT}/${f}" && ! -f "${PROJECT_ROOT}/bin/${f}" ]]; then
            mv "${PROJECT_ROOT}/${f}" "${PROJECT_ROOT}/bin/${f}"
        fi
    done

    for f in \
        common.py \
        request_backend.py \
        run_backend.py \
        check_replies.py \
        cleanup_history.py \
        admin_config_backend.py \
        notify_backend.py \
        admin-init.sh \
        user-init.sh
    do
        if [[ -f "${PROJECT_ROOT}/${f}" && ! -f "${PROJECT_ROOT}/libexec/privilege-approval/${f}" ]]; then
            mv "${PROJECT_ROOT}/${f}" "${PROJECT_ROOT}/libexec/privilege-approval/${f}"
        fi
    done

    for f in *.service *.path *.timer; do
        [[ -e "${f}" ]] || continue
        if [[ -f "${PROJECT_ROOT}/${f}" && ! -f "${PROJECT_ROOT}/systemd/${f}" ]]; then
            mv "${PROJECT_ROOT}/${f}" "${PROJECT_ROOT}/systemd/${f}"
        fi
    done

    if [[ -f "${PROJECT_ROOT}/privilege-approval-sudoer" && ! -f "${PROJECT_ROOT}/sudoers/privilege-approval-sudoer" ]]; then
        mv "${PROJECT_ROOT}/privilege-approval-sudoer" "${PROJECT_ROOT}/sudoers/privilege-approval-sudoer"
    fi
}

require_file() {
    local path="$1"
    if [[ ! -f "${path}" ]]; then
        echo "ERROR: required file missing: ${path}" >&2
        exit 1
    fi
}

validate_project_files() {
    require_file "${PROJECT_ROOT}/bin/request-privilege"
    require_file "${PROJECT_ROOT}/bin/run-approved"

    require_file "${PROJECT_ROOT}/libexec/privilege-approval/common.py"
    require_file "${PROJECT_ROOT}/libexec/privilege-approval/request_backend.py"
    require_file "${PROJECT_ROOT}/libexec/privilege-approval/run_approved.py"
    require_file "${PROJECT_ROOT}/libexec/privilege-approval/check_replies.py"
    require_file "${PROJECT_ROOT}/libexec/privilege-approval/cleanup_history.py"
    require_file "${PROJECT_ROOT}/libexec/privilege-approval/admin_config_backend.py"
    require_file "${PROJECT_ROOT}/libexec/privilege-approval/notify_backend.py"

    require_file "${PROJECT_ROOT}/libexec/privilege-approval/admin-init.sh"
    require_file "${PROJECT_ROOT}/libexec/privilege-approval/user-init.sh"

    require_file "${PROJECT_ROOT}/sudoers/privilege-approval-sudoer"

    require_file "${PROJECT_ROOT}/systemd/privilege-approval-check.service"
    require_file "${PROJECT_ROOT}/systemd/privilege-approval-check.path"
    require_file "${PROJECT_ROOT}/systemd/privilege-approval-check.timer"
    require_file "${PROJECT_ROOT}/systemd/privilege-approval-cleanup.service"
    require_file "${PROJECT_ROOT}/systemd/privilege-approval-cleanup.timer"
}

install_packages_if_needed() {
    if ! command -v python3 >/dev/null 2>&1; then
        apt-get update
        apt-get install -y python3
    fi

    if ! command -v visudo >/dev/null 2>&1; then
        apt-get update
        apt-get install -y sudo
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        echo "ERROR: systemctl not found. This installer expects a systemd-based Ubuntu Server." >&2
        exit 1
    fi
}

create_group() {
    if ! getent group "${GROUP_NAME}" >/dev/null; then
        groupadd --system "${GROUP_NAME}"
    fi
}

install_dirs() {
    install -d -o root -g root -m 0750 "${LIBEXEC_DIR}"
    install -d -o root -g root -m 0750 "${ETC_DIR}"
    install -d -o root -g root -m 0750 "${USERS_DIR}"

    install -d -o root -g root -m 0750 "${STATE_DIR}"
    install -d -o root -g root -m 0750 "${STATE_DIR}/pending"
    install -d -o root -g root -m 0750 "${STATE_DIR}/approved"
    install -d -o root -g root -m 0750 "${STATE_DIR}/running"
    install -d -o root -g root -m 0750 "${STATE_DIR}/done"
    install -d -o root -g root -m 0750 "${STATE_DIR}/rejected"
    install -d -o root -g root -m 0750 "${STATE_DIR}/locks"

    install -d -o root -g root -m 0750 "${LOG_DIR}"
    install -d -o root -g root -m 0700 "${SUDO_IO_DIR}"
}

install_programs() {
    install -o root -g root -m 0755 "${PROJECT_ROOT}/bin/request-privilege" "${BIN_DIR}/request-privilege"
    install -o root -g root -m 0755 "${PROJECT_ROOT}/bin/run-approved" "${BIN_DIR}/run-approved"

    for f in "${PROJECT_ROOT}/libexec/privilege-approval/"*.py; do
        install -o root -g root -m 0755 "${f}" "${LIBEXEC_DIR}/$(basename "${f}")"
    done

    for f in "${PROJECT_ROOT}/libexec/privilege-approval/"*.sh; do
        install -o root -g root -m 0755 "${f}" "${LIBEXEC_DIR}/$(basename "${f}")"
    done
}

install_systemd_units() {
    for f in "${PROJECT_ROOT}/systemd/"*.service "${PROJECT_ROOT}/systemd/"*.path "${PROJECT_ROOT}/systemd/"*.timer; do
        [[ -f "${f}" ]] || continue
        install -o root -g root -m 0644 "${f}" "${SYSTEMD_DIR}/$(basename "${f}")"
    done

    systemctl daemon-reload
    systemctl enable --now privilege-approval-check.path
    systemctl enable --now privilege-approval-check.timer
    systemctl enable --now privilege-approval-cleanup.timer
}

install_sudoers() {
    local tmp
    tmp="$(mktemp)"

    install -o root -g root -m 0440 "${PROJECT_ROOT}/sudoers/privilege-approval-sudoer" "${tmp}"
    visudo -cf "${tmp}"

    install -o root -g root -m 0440 "${tmp}" "${SUDOERS_TARGET}"
    rm -f "${tmp}"

    visudo -cf "${SUDOERS_TARGET}"
}

main() {
    need_root
    arrange_flat_layout_if_needed
    validate_project_files
    install_packages_if_needed
    create_group
    install_dirs
    install_programs
    install_sudoers
    install_systemd_units

    echo
    echo "Installed ${PROJECT_NAME}."
    echo
    echo "Next steps:"
    echo "  1. Run: sudo request-privilege admininit"
    echo "  2. Add users to the group:"
    echo "       sudo usermod -aG ${GROUP_NAME} <username>"
    echo "  3. The user must log out and back in."
    echo "  4. The user runs:"
    echo "       request-privilege init"
}

main "$@"