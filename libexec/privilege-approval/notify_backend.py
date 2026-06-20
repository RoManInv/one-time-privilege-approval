#!/usr/bin/env python3
import argparse
from datetime import datetime, timezone
import hmac
import os
import re
import smtplib
import sys
import time
from email.message import EmailMessage
from zoneinfo import ZoneInfo

from common import (
    global_env,
    load_env_file,
    save_env_file,
    user_profile_path,
    generate_run_password,
    run_password_hash,
    require_real_user,
    mask_secret,
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

VERIFY_TIMEOUT_SEC = 1800

def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)

def send_system_email(to_addr, subject, body):
    g = global_env()

    smtp_host = g.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(g.get("SMTP_PORT", "587"))

    smtp_from = g["WORKFLOW_EMAIL_ADDRESS"]
    smtp_user = g["WORKFLOW_EMAIL_USER"]
    smtp_password = g["WORKFLOW_EMAIL_APP_PASSWORD"]

    msg = EmailMessage()
    msg["From"] = smtp_from
    msg["To"] = to_addr
    msg["Reply-To"] = smtp_from
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as s:
        s.starttls()
        s.login(smtp_user, smtp_password)
        s.send_message(msg)

def load_profile_for_user(username):
    path = user_profile_path(username)
    return path, load_env_file(path)

def save_profile_for_user(username, env):
    path = user_profile_path(username)
    path.parent.mkdir(parents=True, exist_ok=True)
    save_env_file(path, env, mode=0o640)
    os.chown(path, 0, 0)

def cmd_show(args):
    username, _, _ = require_real_user()
    path, env = load_profile_for_user(username)

    if not env:
        print("No notification email configured.")
        print("Use: request-privilege notify set you@example.com")
        return

    print(f"Profile file: {path}")
    print(f'NOTIFY_TO="{env.get("NOTIFY_TO", "")}"')

    if env.get("PENDING_NOTIFY_TO"):
        print(f'PENDING_NOTIFY_TO="{env["PENDING_NOTIFY_TO"]}"')
        print(f'PENDING_EXPIRES_AT="{env.get("PENDING_EXPIRES_AT", "")}"')

def cmd_set(args):
    g = global_env()
    username, _, _ = require_real_user()
    email = args.email.strip()

    if not EMAIL_RE.match(email):
        die("email address does not look valid")

    path, env = load_profile_for_user(username)

    token = generate_run_password(24)
    salt = generate_run_password(16)
    # expires_at = int(time.time()) + VERIFY_TIMEOUT_SEC

    tz = g.get("TZ", "UTC")
    try:
        ZoneInfo(tz)
    except Exception:
        tz = "UTC"
    expires_at = datetime.fromtimestamp(expires_at, timezone.utc).astimezone(ZoneInfo(tz)).strftime("%Y-%m-%d %H:%M:%S %Z")

    old_email = env.get("NOTIFY_TO")

    env["PENDING_NOTIFY_TO"] = email
    env["PENDING_TOKEN_SALT"] = salt
    env["PENDING_TOKEN_HASH"] = run_password_hash(token, salt)
    env["PENDING_EXPIRES_AT"] = str(expires_at)

    save_profile_for_user(username, env)

    send_system_email(
        email,
        "[privilege approval] verify notification email",
        f"""A notification email change was requested for Linux user:

{username}

To activate this address, run:

request-privilege notify verify {token}

This verification token expires in 30 minutes.

If you did not request this, ignore this email.
"""
    )

    if old_email:
        try:
            send_system_email(
                old_email,
                "[privilege approval] notification email change requested",
                f"""A notification email change was requested for Linux user:

{username}

Pending new address:
{email}

If this was not you, contact the administrator.
"""
            )
        except Exception:
            pass

    print(f"Verification email sent to {email}.")
    print("Run:")
    print(f"  request-privilege notify verify <token-from-email>")

def cmd_verify(args):
    username, _, _ = require_real_user()
    token = args.token.strip()

    path, env = load_profile_for_user(username)

    pending_email = env.get("PENDING_NOTIFY_TO")
    salt = env.get("PENDING_TOKEN_SALT")
    expected_hash = env.get("PENDING_TOKEN_HASH")
    expires_at = int(env.get("PENDING_EXPIRES_AT", "0") or "0")

    if not pending_email or not salt or not expected_hash:
        die("no pending notification email change")

    if int(time.time()) > expires_at:
        for k in ["PENDING_NOTIFY_TO", "PENDING_TOKEN_SALT", "PENDING_TOKEN_HASH", "PENDING_EXPIRES_AT"]:
            env.pop(k, None)
        save_profile_for_user(username, env)
        die("verification token expired; run notify set again")

    actual_hash = run_password_hash(token, salt)

    if not hmac.compare_digest(actual_hash, expected_hash):
        die("bad verification token")

    env["NOTIFY_TO"] = pending_email

    for k in ["PENDING_NOTIFY_TO", "PENDING_TOKEN_SALT", "PENDING_TOKEN_HASH", "PENDING_EXPIRES_AT"]:
        env.pop(k, None)

    save_profile_for_user(username, env)

    print(f'Notification email activated: {pending_email}')

def cmd_cancel(args):
    username, _, _ = require_real_user()
    path, env = load_profile_for_user(username)

    changed = False
    for k in ["PENDING_NOTIFY_TO", "PENDING_TOKEN_SALT", "PENDING_TOKEN_HASH", "PENDING_EXPIRES_AT"]:
        if k in env:
            changed = True
            env.pop(k, None)

    if changed:
        save_profile_for_user(username, env)
        print("pending notification email change cancelled")
    else:
        print("no pending notification email change")

def main():
    parser = argparse.ArgumentParser(prog="request-privilege notify")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("show")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("set")
    p.add_argument("email")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("verify")
    p.add_argument("token")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("cancel")
    p.set_defaults(func=cmd_cancel)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()