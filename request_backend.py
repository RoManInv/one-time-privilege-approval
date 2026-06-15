#!/usr/bin/env python3
import argparse
import os
import pwd
import shlex
import shutil
import smtplib
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

from common import (
    PENDING,
    SECURE_PATH,
    global_env,
    load_user_email_config,
    cfg_int,
    approval_hash,
    safe_request_id,
    atomic_write_json,
)

SHELL_PATHS = {
    "/bin/sh", "/usr/bin/sh",
    "/bin/bash", "/usr/bin/bash",
    "/bin/dash", "/usr/bin/dash",
    "/bin/zsh", "/usr/bin/zsh",
}

def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)

def real_request_user():
    user = os.environ.get("SUDO_USER")
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not user or not uid or not gid:
        die("must be invoked through sudo wrapper")
    return user, int(uid), int(gid)

def resolve_executable(exe):
    if exe.startswith("/"):
        if not os.path.exists(exe):
            die(f"executable does not exist: {exe}")
        return exe

    resolved = shutil.which(exe, path=SECURE_PATH)
    if not resolved:
        die(f"executable not found in secure path: {exe}")
    return resolved

def parse_command_line(line, current_cwd, allow_shells):
    original = line.rstrip("\n")
    stripped = original.strip()

    if not stripped or stripped.startswith("#"):
        return None, current_cwd

    try:
        parts = shlex.split(stripped, posix=True)
    except ValueError as e:
        die(f"cannot parse command line: {original}\n{e}")

    if not parts:
        return None, current_cwd

    # In file mode, allow cd to set cwd for following commands.
    if parts[0] == "cd":
        if len(parts) != 2:
            die(f"cd line must be exactly: cd <directory>\nline: {original}")
        new_cwd = parts[1]
        if not new_cwd.startswith("/"):
            new_cwd = os.path.abspath(os.path.join(current_cwd, new_cwd))
        return {"type": "cwd", "original": original, "cwd": new_cwd}, new_cwd

    # User may write sudo or not.
    if parts[0] == "sudo":
        parts = parts[1:]
        if not parts:
            die("sudo without a command is not allowed")
        if parts[0].startswith("-"):
            die("sudo options are not supported; write the target command directly")

    exe = resolve_executable(parts[0])
    parts[0] = exe

    if not allow_shells and exe in SHELL_PATHS:
        die(
            f"shell command is disabled by policy: {exe}\n"
            "Do not approve shell wrappers unless you intentionally accept that risk."
        )

    return {
        "type": "exec",
        "original": original,
        "argv": parts,
        "cwd": current_cwd,
        "timeout_sec": 3600,
    }, current_cwd

def read_commands(args):
    if args.file:
        p = Path(args.file)
        if not p.exists():
            die(f"command file does not exist: {p}")
        return p.read_text(encoding="utf-8").splitlines()

    if not args.command:
        die("provide either a command or -f <file>")

    return [" ".join(args.command)]

def clamp_retention(requested, env):
    default_days = cfg_int(env, "DEFAULT_RETENTION_DAYS", 30)
    min_days = cfg_int(env, "MIN_RETENTION_DAYS", 7)
    max_days = cfg_int(env, "MAX_RETENTION_DAYS", 365)

    if requested is None:
        requested = default_days

    return max(min_days, min(max_days, int(requested)))

def send_request_email(username, subject, body):
    g = global_env()
    u = load_user_email_config(username)

    approver = g["APPROVER_EMAIL"]

    smtp_host = u.get("SMTP_HOST") or g.get("DEFAULT_SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(u.get("SMTP_PORT") or g.get("DEFAULT_SMTP_PORT", "587"))

    smtp_from = u["SMTP_FROM"]
    smtp_user = u["SMTP_USER"]
    smtp_password = u["SMTP_APP_PASSWORD"]

    msg = EmailMessage()
    msg["From"] = smtp_from
    msg["To"] = approver
    msg["Reply-To"] = smtp_from
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as s:
        s.starttls()
        s.login(smtp_user, smtp_password)
        s.send_message(msg)

def main():
    parser = argparse.ArgumentParser(prog="request-privilege")
    parser.add_argument("-f", "--file", help="file containing one command per line")
    parser.add_argument("--retention-days", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    g = global_env()
    allow_shells = g.get("ALLOW_SHELL_COMMANDS", "no").lower() in {"1", "yes", "true"}
    timeout_sec = cfg_int(g, "REQUEST_TIMEOUT_SEC", 3600)

    requester, requester_uid, requester_gid = real_request_user()
    pw = pwd.getpwnam(requester)
    request_cwd = os.environ.get("PWD") or pw.pw_dir
    if not request_cwd.startswith("/"):
        request_cwd = pw.pw_dir

    lines = read_commands(args)
    current_cwd = request_cwd
    commands = []
    notes = []

    for line in lines:
        item, current_cwd = parse_command_line(line, current_cwd, allow_shells)
        if item is None:
            continue
        if item["type"] == "cwd":
            notes.append(item)
        else:
            commands.append(item)

    if not commands:
        die("no executable commands found")

    now = int(time.time())
    expires_at = now + timeout_sec
    retention_days = clamp_retention(args.retention_days, g)
    request_id = safe_request_id(f"{now}-{uuid.uuid4().hex[:10]}")

    manifest = {
        "approval": {
            "request_id": request_id,
            "requester": requester,
            "requester_uid": requester_uid,
            "requester_gid": requester_gid,
            "request_cwd": request_cwd,
            "created_at_epoch": now,
            "expires_at_epoch": expires_at,
            "retention_days": retention_days,
            "commands": commands,
            "notes": notes,
        },
        "state": {
            "status": "pending",
            "failed_otp_attempts": 0,
            "max_otp_attempts": cfg_int(g, "MAX_OTP_ATTEMPTS", 5),
        },
    }

    digest = approval_hash(manifest)
    target = PENDING / f"{request_id}.json"
    atomic_write_json(target, manifest)

    expires_utc = datetime.fromtimestamp(expires_at, timezone.utc).astimezone(ZoneInfo("Europe/Berlin")).strftime("%Y-%m-%d %H:%M:%S %Z")

    command_text = "\n".join(
        f"{i + 1}. cwd={cmd['cwd']} :: {' '.join(shlex.quote(x) for x in cmd['argv'])}"
        for i, cmd in enumerate(commands)
    )

    subject = f"[privilege approval] {requester} request {request_id}"

    body = f"""A one-time privileged command request was created.

Requester:
{requester}

Request ID:
{request_id}

SHA256 digest:
{digest}

Approval deadline:
{expires_utc}

Requested retention:
{retention_days} day(s)

Commands, in exact execution order:
{command_text}

To approve, reply with exactly one line:

APPROVE {request_id} {digest} <6-digit-OTP>

To reject, reply with exactly one line:

REJECT {request_id} {digest}

Do not approve if the command list, request ID, or digest is not exactly expected.
"""

    send_request_email(requester, subject, body)

    print(f"request_id={request_id}")
    print(f"sha256={digest}")
    print(f"expires_at={expires_utc}")
    print()
    print("The administrator should reply to the request email with either:")
    print(f"  APPROVE {request_id} {digest} <OTP>")
    print(f"  REJECT {request_id} {digest}")
    print()
    print("After approval, run:")
    print(f"  run-approved {request_id} {digest} <OTP>")

if __name__ == "__main__":
    main()