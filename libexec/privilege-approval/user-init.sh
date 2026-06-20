#!/usr/bin/env bash
set -euo pipefail

GROUP_NAME="privilege-requesters"

need_non_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        echo "ERROR: user initialization must be run as the normal requester, not with sudo." >&2
        echo "Run: request-privilege init" >&2
        exit 1
    fi
}

need_group() {
    if ! id -nG | tr ' ' '\n' | grep -qx "${GROUP_NAME}"; then
        echo "ERROR: user $(id -un) is not in group ${GROUP_NAME}." >&2
        echo "Ask the administrator to run:" >&2
        echo "  sudo usermod -aG ${GROUP_NAME} $(id -un)" >&2
        echo "Then log out and back in before running this script again." >&2
        exit 1
    fi
}

need_command() {
    if ! command -v request-privilege >/dev/null 2>&1; then
        echo "ERROR: request-privilege command not found in PATH." >&2
        echo "Ask the administrator to install the project first." >&2
        exit 1
    fi
}

prompt_email() {
    local email
    while true; do
        read -r -p "Notification email address: " email
        if [[ "${email}" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
            printf '%s' "${email}"
            return
        fi
        echo "Email address does not look valid."
    done
}

main() {
    need_non_root
    need_group
    need_command

    echo "Privilege Approval user initialization for $(id -un)"
    echo

    request-privilege notify show || true
    echo

    local email
    email="$(prompt_email)"

    echo
    echo "Sending verification email to ${email}..."
    request-privilege notify set "${email}"

    echo
    echo "Check ${email} for the verification token."
    echo

    local token
    read -r -p "Verification token: " token

    request-privilege notify verify "${token}"

    echo
    echo "User initialization complete."
    echo
    echo "You can now create a request, for example:"
    echo "  request-privilege \"sudo touch /etc/test-approved\""
}

main "$@"