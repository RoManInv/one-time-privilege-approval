#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import pwd
import struct
import time
from pathlib import Path

BASE = Path("/var/lib/privilege-approval")
PENDING = BASE / "pending"
APPROVED = BASE / "approved"
RUNNING = BASE / "running"
DONE = BASE / "done"
REJECTED = BASE / "rejected"
LOCKS = BASE / "locks"

LOG_DIR = Path("/var/log/privilege-approval")
CONFIG = Path("/etc/privilege-approval/config.env")
TOTP_SECRET = Path("/etc/privilege-approval/totp.secret")

SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

def load_env_file(path):
    env = {}
    p = Path(path)
    if not p.exists():
        return env
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k] = v.strip().strip('"').strip("'")
    return env

def global_env():
    return load_env_file(CONFIG)

def cfg_int(env, key, default):
    try:
        return int(env.get(key, default))
    except Exception:
        return default

def user_home(username):
    return Path(pwd.getpwnam(username).pw_dir)

def user_email_config_path(username):
    return user_home(username) / ".config" / "privilege-approval" / "email.env"

def load_user_email_config(username):
    path = user_email_config_path(username)
    st = path.stat()

    # Require user-owned config and no group/other access.
    pw = pwd.getpwnam(username)
    if st.st_uid != pw.pw_uid:
        raise RuntimeError(f"{path} must be owned by {username}")
    if st.st_mode & 0o077:
        raise RuntimeError(f"{path} must be chmod 0600")

    return load_env_file(path)

def canonical_bytes(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

def approval_hash(manifest):
    return hashlib.sha256(canonical_bytes(manifest["approval"])).hexdigest()

def safe_request_id(s):
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    return "".join(c for c in s if c in allowed)

def atomic_write_json(path, obj, mode=0o640):
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)

def normalize_base32_secret(secret):
    s = secret.strip().replace(" ", "").upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    return s

def hotp(secret_b32, counter, digits=6):
    key = base64.b32decode(normalize_base32_secret(secret_b32))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)

def verify_totp(code, past_sec=240, future_sec=30):
    if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
        return False

    secret = TOTP_SECRET.read_text(encoding="utf-8").strip()
    now = int(time.time())
    step = 30

    start_counter = (now - past_sec) // step
    end_counter = (now + future_sec) // step

    for counter in range(start_counter, end_counter + 1):
        expected = hotp(secret, counter)
        if hmac.compare_digest(expected, code):
            return True

    return False

def acquire_lock(request_id):
    lock_path = LOCKS / f"{request_id}.lock"
    os.mkdir(lock_path)
    return lock_path

def release_lock(lock_path):
    try:
        os.rmdir(lock_path)
    except Exception:
        pass