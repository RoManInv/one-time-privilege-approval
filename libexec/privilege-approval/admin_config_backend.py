#!/usr/bin/env python3
import argparse
import getpass
import os
import re
import sys

from common import CONFIG, global_env, save_env_file, mask_secret

SECRET_KEYS = {
    "WORKFLOW_EMAIL_APP_PASSWORD",
}

ALLOWED_KEYS = {
    "APPROVER_EMAIL": "email",
    "WORKFLOW_EMAIL_ADDRESS": "email",
    "WORKFLOW_EMAIL_USER": "email",
    "WORKFLOW_EMAIL_APP_PASSWORD": "secret",

    "SMTP_HOST": "string",
    "SMTP_PORT": "int",
    "IMAP_HOST": "string",
    "IMAP_PORT": "int",

    "REQUEST_TIMEOUT_SEC": "int",
    "TOTP_ACCEPT_PAST_SEC": "int",
    "TOTP_ACCEPT_FUTURE_SEC": "int",

    "RUN_AFTER_APPROVAL_TIMEOUT_SEC": "int",
    "RUN_PASSWORD_BYTES": "int",
    "RUN_PASSWORD_MAX_ATTEMPTS": "int",

    "MAX_OTP_ATTEMPTS": "int",

    "DEFAULT_RETENTION_DAYS": "int",
    "MIN_RETENTION_DAYS": "int",
    "MAX_RETENTION_DAYS": "int",

    "ALLOW_SHELL_COMMANDS": "bool",
    "POLL_INTERVAL_SEC": "int",

    "TZ": "string",
}

ALLOWED_KEYS_DESCRIPTIONS = {
    "APPROVER_EMAIL": "Email address to send approval requests to",
    "WORKFLOW_EMAIL_ADDRESS": "Email address for workflow notifications",
    "WORKFLOW_EMAIL_USER": "Email user for workflow notifications",
    "WORKFLOW_EMAIL_APP_PASSWORD": "App password for workflow email account",

    "SMTP_HOST": "SMTP server hostname",
    "SMTP_PORT": "SMTP server port",
    "IMAP_HOST": "IMAP server hostname",
    "IMAP_PORT": "IMAP server port",

    "REQUEST_TIMEOUT_SEC": "Request timeout in seconds",
    "TOTP_ACCEPT_PAST_SEC": "TOTP acceptance window for past seconds",
    "TOTP_ACCEPT_FUTURE_SEC": "TOTP acceptance window for future seconds",

    "RUN_AFTER_APPROVAL_TIMEOUT_SEC": "Timeout for running commands after approval",
    "RUN_PASSWORD_BYTES": "Number of bytes for run passwords",
    "RUN_PASSWORD_MAX_ATTEMPTS": "Maximum attempts for run passwords",

    "MAX_OTP_ATTEMPTS": "Maximum OTP verification attempts",

    "DEFAULT_RETENTION_DAYS": "Default number of days to retain request data",
    "MIN_RETENTION_DAYS": "Minimum number of days to retain request data",
    "MAX_RETENTION_DAYS": "Maximum number of days to retain request data",

    "ALLOW_SHELL_COMMANDS": "Allow execution of shell commands, yes/no or true/false",
    "POLL_INTERVAL_SEC": "Polling interval in seconds",

    "TZ": "Timezone for displaying times (e.g. 'UTC' or 'America/New_York')",
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)

def require_root():
    if os.geteuid() != 0:
        die("config management must be run as root; use: sudo request-privilege config ...")

def validate_value(key, value):
    kind = ALLOWED_KEYS[key]

    if kind == "email":
        if not EMAIL_RE.match(value):
            die(f"{key} must look like an email address")
        return value

    if kind == "int":
        try:
            iv = int(value)
        except Exception:
            die(f"{key} must be an integer")
        if iv < 0:
            die(f"{key} must not be negative")
        return str(iv)

    if kind == "bool":
        v = value.lower()
        if v not in {"yes", "no", "true", "false"}:
            die(f'{key} must be "yes"/"no" or "true"/"false"')
        if v in {"yes", "true"}:
            v = "yes"
        if v in {"no", "false"}:
            v = "no"
        return v

    if kind in {"string", "secret"}:
        if not value:
            die(f"{key} must not be empty")
        return value

    die(f"unknown type for {key}")

def cmd_show(args):
    env = global_env()

    for key in sorted(ALLOWED_KEYS.keys()):
        if key not in env:
            continue
        value = env[key]
        if key in SECRET_KEYS and not args.reveal_secrets:
            value = mask_secret(value)
        print(f'{key}="{value}"')

def cmd_set(args):
    env = global_env()

    key = args.key
    if key not in ALLOWED_KEYS:
        die(f"unsupported config key: {key}")

    env[key] = validate_value(key, args.value)
    save_env_file(CONFIG, env, mode=0o600)
    print(f"updated {key}")

def cmd_set_secret(args):
    env = global_env()

    key = args.key
    if key not in SECRET_KEYS:
        die(f"{key} is not a secret key managed by set-secret")

    v1 = getpass.getpass(f"Enter {key}: ")
    v2 = getpass.getpass(f"Confirm {key}: ")

    if v1 != v2:
        die("secret values do not match")

    env[key] = validate_value(key, v1)
    save_env_file(CONFIG, env, mode=0o600)
    print(f"updated {key}")

def cmd_unset(args):
    env = global_env()

    key = args.key
    if key not in ALLOWED_KEYS:
        die(f"unsupported config key: {key}")

    if key in env:
        del env[key]
        save_env_file(CONFIG, env, mode=0o600)
        print(f"removed {key}")
    else:
        print(f"{key} was not set")

def print_help():
    print(f"Usage: request-privilege config <command> [arg] [value]")
    print("Commands:")
    print("  show: Display current configuration")
    print("  set: Set a configuration value")
    print("  set-secret: Set a secret configuration value")
    print("  unset: Unset a configuration value")
    print("  help: Display this help message")
    print()
    print("Configuration Keys:")
    for k, v in ALLOWED_KEYS_DESCRIPTIONS.items():
        print(f"  {k}: {v}")

def main():
    require_root()

    parser = argparse.ArgumentParser(prog="request-privilege config")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("show")
    p.add_argument("--reveal-secrets", action="store_true")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("set")
    p.add_argument("key")
    p.add_argument("value")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("set-secret")
    p.add_argument("key")
    p.set_defaults(func=cmd_set_secret)

    p = sub.add_parser("unset")
    p.add_argument("key")
    p.set_defaults(func=cmd_unset)

    p = sub.add_parser("help")
    p.set_defaults(func=lambda args: print_help())

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()