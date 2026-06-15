#!/usr/bin/env python3
import email
import imaplib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from email.utils import parseaddr
from collections import defaultdict

from common import (
    PENDING,
    APPROVED,
    REJECTED,
    global_env,
    load_user_email_config,
    cfg_int,
    approval_hash,
    verify_totp,
    atomic_write_json,
)

APPROVE_RE = re.compile(
    r"^\s*APPROVE\s+([A-Za-z0-9_.-]+)\s+([a-fA-F0-9]{64})\s+([0-9]{6})\s*$",
    re.MULTILINE,
)

REJECT_RE = re.compile(
    r"^\s*REJECT\s+([A-Za-z0-9_.-]+)\s+([a-fA-F0-9]{64})\s*$",
    re.MULTILINE,
)

def log(msg):
    print(f"[privilege-check] {msg}", flush=True)

def get_body(msg):
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    parts.append(payload.decode(charset, errors="replace"))
        return "\n".join(parts)

    payload = msg.get_payload(decode=True)
    if not payload:
        return ""

    charset = msg.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="replace")

def move_request(path, target_dir, suffix=None):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    rid = manifest["approval"]["request_id"]

    if suffix:
        target = target_dir / f"{rid}.{suffix}.json"
    else:
        target = target_dir / f"{rid}.json"

    if target.exists():
        target = target_dir / f"{rid}.{suffix or 'moved'}.{int(time.time())}.json"

    shutil.move(str(path), str(target))
    return target

def reject_request(path, reason):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["state"]["status"] = "rejected"
    manifest["state"]["reason"] = reason
    manifest["state"]["rejected_at_epoch"] = int(time.time())
    atomic_write_json(path, manifest)
    target = move_request(path, REJECTED, reason)
    log(f"rejected {manifest['approval']['request_id']}: {reason}")
    return target

def approve_request(path):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["state"]["status"] = "approved"
    manifest["state"]["approved_at_epoch"] = int(time.time())
    atomic_write_json(path, manifest)
    target = move_request(path, APPROVED, None)
    log(f"approved {manifest['approval']['request_id']}")
    return target

def expire_old_pending():
    now = int(time.time())
    for path in list(PENDING.glob("*.json")):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
            expires_at = int(manifest["approval"].get("expires_at_epoch", 0))
            if not expires_at or now > expires_at:
                reject_request(path, "expired")
        except Exception as e:
            log(f"failed to expire-check {path}: {e}")

def pending_by_user():
    result = defaultdict(list)

    for path in sorted(PENDING.glob("*.json")):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
            user = manifest["approval"]["requester"]
            result[user].append(path)
        except Exception as e:
            log(f"bad pending file {path}: {e}")

    return result

def find_pending_for_user(user, rid):
    path = PENDING / f"{rid}.json"
    if not path.exists():
        return None

    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest["approval"]["requester"] != user:
            return None
        return path
    except Exception:
        return None

def process_mail_for_user(user):
    g = global_env()
    u = load_user_email_config(user)

    approver = g["APPROVER_EMAIL"].lower()

    imap_host = u.get("IMAP_HOST") or g.get("DEFAULT_IMAP_HOST", "imap.gmail.com")
    imap_port = int(u.get("IMAP_PORT") or g.get("DEFAULT_IMAP_PORT", "993"))
    imap_user = u["IMAP_USER"]
    imap_password = u["IMAP_APP_PASSWORD"]

    approved_or_rejected = 0

    M = imaplib.IMAP4_SSL(imap_host, imap_port)
    M.login(imap_user, imap_password)
    M.select("INBOX")

    status, data = M.search(None, "UNSEEN")
    if status != "OK":
        M.logout()
        return 0

    for num in data[0].split():
        status, msg_data = M.fetch(num, "(RFC822)")
        if status != "OK":
            continue

        msg = email.message_from_bytes(msg_data[0][1])
        sender = parseaddr(msg.get("From", ""))[1].lower()
        body = get_body(msg)

        if sender != approver:
            continue

        approve_match = APPROVE_RE.search(body)
        reject_match = REJECT_RE.search(body)

        if not approve_match and not reject_match:
            continue

        if approve_match:
            rid, claimed_digest, otp = approve_match.groups()
            path = find_pending_for_user(user, rid)
            if not path:
                M.store(num, "+FLAGS", "\\Seen")
                continue

            manifest = json.loads(path.read_text(encoding="utf-8"))
            actual_digest = approval_hash(manifest)

            if claimed_digest.lower() != actual_digest.lower():
                reject_request(path, "hash-mismatch")
                M.store(num, "+FLAGS", "\\Seen")
                approved_or_rejected += 1
                continue

            now = int(time.time())
            expires_at = int(manifest["approval"]["expires_at_epoch"])
            if now > expires_at:
                reject_request(path, "expired")
                M.store(num, "+FLAGS", "\\Seen")
                approved_or_rejected += 1
                continue

            past_sec = cfg_int(g, "TOTP_ACCEPT_PAST_SEC", 240)
            future_sec = cfg_int(g, "TOTP_ACCEPT_FUTURE_SEC", 30)
            if not verify_totp(otp, past_sec=past_sec, future_sec=future_sec):
                reject_request(path, "bad-approval-otp")
                M.store(num, "+FLAGS", "\\Seen")
                approved_or_rejected += 1
                continue

            approve_request(path)
            M.store(num, "+FLAGS", "\\Seen")
            approved_or_rejected += 1
            continue

        if reject_match:
            rid, claimed_digest = reject_match.groups()
            path = find_pending_for_user(user, rid)
            if not path:
                M.store(num, "+FLAGS", "\\Seen")
                continue

            manifest = json.loads(path.read_text(encoding="utf-8"))
            actual_digest = approval_hash(manifest)

            if claimed_digest.lower() != actual_digest.lower():
                reject_request(path, "reject-hash-mismatch")
            else:
                reject_request(path, "admin-rejected")

            M.store(num, "+FLAGS", "\\Seen")
            approved_or_rejected += 1

    M.logout()
    return approved_or_rejected

def pending_exists():
    return any(PENDING.glob("*.json"))

def main():
    loop = "--loop" in sys.argv
    g = global_env()
    poll_interval = cfg_int(g, "POLL_INTERVAL_SEC", 60)

    while True:
        expire_old_pending()

        grouped = pending_by_user()
        if not grouped:
            log("no pending requests; exiting")
            return 0

        for user in grouped.keys():
            try:
                process_mail_for_user(user)
            except Exception as e:
                log(f"mail check failed for {user}: {e}")

        expire_old_pending()

        if not pending_exists():
            log("no pending requests after check; exiting")
            return 0

        if not loop:
            return 0

        log(f"pending requests remain; sleeping {poll_interval} seconds")
        time.sleep(poll_interval)

if __name__ == "__main__":
    raise SystemExit(main())