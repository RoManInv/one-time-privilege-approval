#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="privilege-approval"
ETC_DIR="/etc/${PROJECT_NAME}"
CONFIG_FILE="${ETC_DIR}/config.env"
TOTP_FILE="${ETC_DIR}/totp.secret"

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "ERROR: admin initialization must be run as root." >&2
        echo "Run: sudo request-privilege admininit" >&2
        exit 1
    fi
}

escape_value() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

urlencode() {
    python3 - "$1" <<'PY'
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe=""))
PY
}

show_totp_qr() {
    local issuer="$1"
    local account="$2"
    local secret="$3"

    local issuer_enc
    local account_enc
    local label
    local uri

    issuer_enc="$(urlencode "${issuer}")"
    account_enc="$(urlencode "${account}")"

    label="${issuer_enc}:${account_enc}"
    uri="otpauth://totp/${label}?secret=${secret}&issuer=${issuer_enc}&algorithm=SHA1&digits=6&period=30"

    echo
    echo "Scan this QR code with your authenticator app:"
    echo

    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ANSIUTF8 "${uri}"
    else
        echo "WARNING: qrencode is not installed; cannot display QR code."
        echo "Install it with: sudo apt install qrencode"
    fi

    echo
    echo "Manual setup values:"
    echo "  Issuer: ${issuer}"
    echo "  Account: ${account}"
    echo "  Secret: ${secret}"
    echo "  Type: TOTP"
    echo "  Digits: 6"
    echo "  Period: 30 seconds"
}

write_kv() {
    local key="$1"
    local value="$2"
    printf '%s="%s"\n' "${key}" "$(escape_value "${value}")" >> "${CONFIG_FILE}.tmp"
}

prompt() {
    local key="$1"
    local default="$2"
    local value

    if [[ -n "${default}" ]]; then
        read -r -p "${key} [${default}]: " value
        value="${value:-${default}}"
    else
        while true; do
            read -r -p "${key}: " value
            if [[ -n "${value}" ]]; then
                break
            fi
            echo "Value is required."
        done
    fi

    printf '%s' "${value}"
}

prompt_secret() {
    local key="$1"
    local value1
    local value2

    while true; do
        read -r -s -p "${key}: " value1
        echo
        read -r -s -p "Confirm ${key}: " value2
        echo

        if [[ -z "${value1}" ]]; then
            echo "Secret is required."
            continue
        fi

        if [[ "${value1}" != "${value2}" ]]; then
            echo "Secrets do not match."
            continue
        fi

        printf '%s' "${value1}"
        return
    done
}

generate_totp_secret() {
    python3 - <<'PY'
import base64, secrets
print(base64.b32encode(secrets.token_bytes(20)).decode().rstrip("="))
PY
}

main() {
    need_root

    install -d -o root -g root -m 0750 "${ETC_DIR}"

    echo "Administrator configuration initialization"
    echo

    local APPROVER_EMAIL
    local WORKFLOW_EMAIL_ADDRESS
    local WORKFLOW_EMAIL_USER
    local WORKFLOW_EMAIL_APP_PASSWORD
    local SMTP_HOST
    local SMTP_PORT
    local IMAP_HOST
    local IMAP_PORT
    local REQUEST_TIMEOUT_SEC
    local TOTP_ACCEPT_PAST_SEC
    local TOTP_ACCEPT_FUTURE_SEC
    local RUN_AFTER_APPROVAL_TIMEOUT_SEC
    local RUN_PASSWORD_BYTES
    local RUN_PASSWORD_MAX_ATTEMPTS
    local MAX_OTP_ATTEMPTS
    local DEFAULT_RETENTION_DAYS
    local MIN_RETENTION_DAYS
    local MAX_RETENTION_DAYS
    local ALLOW_SHELL_COMMANDS
    local POLL_INTERVAL_SEC
    local TZ

    APPROVER_EMAIL="$(prompt "APPROVER_EMAIL" "")"
    WORKFLOW_EMAIL_ADDRESS="$(prompt "WORKFLOW_EMAIL_ADDRESS" "")"
    WORKFLOW_EMAIL_USER="$(prompt "WORKFLOW_EMAIL_USER" "${WORKFLOW_EMAIL_ADDRESS}")"
    WORKFLOW_EMAIL_APP_PASSWORD="$(prompt_secret "WORKFLOW_EMAIL_APP_PASSWORD")"

    SMTP_HOST="$(prompt "SMTP_HOST" "smtp.gmail.com")"
    SMTP_PORT="$(prompt "SMTP_PORT" "587")"
    IMAP_HOST="$(prompt "IMAP_HOST" "imap.gmail.com")"
    IMAP_PORT="$(prompt "IMAP_PORT" "993")"

    REQUEST_TIMEOUT_SEC="$(prompt "REQUEST_TIMEOUT_SEC" "3600")"

    TOTP_ACCEPT_PAST_SEC="$(prompt "TOTP_ACCEPT_PAST_SEC" "240")"
    TOTP_ACCEPT_FUTURE_SEC="$(prompt "TOTP_ACCEPT_FUTURE_SEC" "30")"

    RUN_AFTER_APPROVAL_TIMEOUT_SEC="$(prompt "RUN_AFTER_APPROVAL_TIMEOUT_SEC" "3600")"
    RUN_PASSWORD_BYTES="$(prompt "RUN_PASSWORD_BYTES" "24")"
    RUN_PASSWORD_MAX_ATTEMPTS="$(prompt "RUN_PASSWORD_MAX_ATTEMPTS" "5")"

    MAX_OTP_ATTEMPTS="$(prompt "MAX_OTP_ATTEMPTS" "5")"

    DEFAULT_RETENTION_DAYS="$(prompt "DEFAULT_RETENTION_DAYS" "30")"
    MIN_RETENTION_DAYS="$(prompt "MIN_RETENTION_DAYS" "7")"
    MAX_RETENTION_DAYS="$(prompt "MAX_RETENTION_DAYS" "365")"

    TZ="$(prompt "TIMEZONE" "UTC")"

    while true; do
        ALLOW_SHELL_COMMANDS="$(prompt "ALLOW_SHELL_COMMANDS" "no")"
        case "${ALLOW_SHELL_COMMANDS}" in
            yes|no) break ;;
            *) echo 'ALLOW_SHELL_COMMANDS must be "yes" or "no".' ;;
        esac
    done

    POLL_INTERVAL_SEC="$(prompt "POLL_INTERVAL_SEC" "60")"

    : > "${CONFIG_FILE}.tmp"
    chmod 0600 "${CONFIG_FILE}.tmp"

    write_kv "APPROVER_EMAIL" "${APPROVER_EMAIL}"
    write_kv "WORKFLOW_EMAIL_ADDRESS" "${WORKFLOW_EMAIL_ADDRESS}"
    write_kv "WORKFLOW_EMAIL_USER" "${WORKFLOW_EMAIL_USER}"
    write_kv "WORKFLOW_EMAIL_APP_PASSWORD" "${WORKFLOW_EMAIL_APP_PASSWORD}"

    write_kv "SMTP_HOST" "${SMTP_HOST}"
    write_kv "SMTP_PORT" "${SMTP_PORT}"
    write_kv "IMAP_HOST" "${IMAP_HOST}"
    write_kv "IMAP_PORT" "${IMAP_PORT}"

    write_kv "REQUEST_TIMEOUT_SEC" "${REQUEST_TIMEOUT_SEC}"

    write_kv "TOTP_ACCEPT_PAST_SEC" "${TOTP_ACCEPT_PAST_SEC}"
    write_kv "TOTP_ACCEPT_FUTURE_SEC" "${TOTP_ACCEPT_FUTURE_SEC}"

    write_kv "RUN_AFTER_APPROVAL_TIMEOUT_SEC" "${RUN_AFTER_APPROVAL_TIMEOUT_SEC}"
    write_kv "RUN_PASSWORD_BYTES" "${RUN_PASSWORD_BYTES}"
    write_kv "RUN_PASSWORD_MAX_ATTEMPTS" "${RUN_PASSWORD_MAX_ATTEMPTS}"

    write_kv "MAX_OTP_ATTEMPTS" "${MAX_OTP_ATTEMPTS}"

    write_kv "DEFAULT_RETENTION_DAYS" "${DEFAULT_RETENTION_DAYS}"
    write_kv "MIN_RETENTION_DAYS" "${MIN_RETENTION_DAYS}"
    write_kv "MAX_RETENTION_DAYS" "${MAX_RETENTION_DAYS}"

    write_kv "ALLOW_SHELL_COMMANDS" "${ALLOW_SHELL_COMMANDS}"
    write_kv "POLL_INTERVAL_SEC" "${POLL_INTERVAL_SEC}"

    write_kv "TIMEZONE" "${TZ}"

    chown root:root "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "${CONFIG_FILE}"
    chmod 0600 "${CONFIG_FILE}"

    echo
    echo "TOTP setup"
    echo "You can paste an existing Base32 TOTP secret, or leave blank to generate one."
    read -r -p "TOTP secret [auto-generate]: " TOTP_SECRET

    if [[ -z "${TOTP_SECRET}" ]]; then
        TOTP_SECRET="$(generate_totp_secret)"
    fi

    printf '%s\n' "${TOTP_SECRET}" > "${TOTP_FILE}.tmp"
    chown root:root "${TOTP_FILE}.tmp"
    chmod 0600 "${TOTP_FILE}.tmp"
    mv "${TOTP_FILE}.tmp" "${TOTP_FILE}"

    echo
    echo "Configuration written:"
    echo "  ${CONFIG_FILE}"
    echo "  ${TOTP_FILE}"
    echo
    echo "Add this TOTP secret to the administrator's authenticator app:"

    show_totp_qr "Ubuntu24-PrivilegeApproval" "${APPROVER_EMAIL}" "${TOTP_SECRET}"

    echo "You can later edit config with:"
    echo "  sudo request-privilege config show"
    echo "  sudo request-privilege config set KEY VALUE"
    echo "  sudo request-privilege config set-secret WORKFLOW_EMAIL_APP_PASSWORD"
}

main "$@"