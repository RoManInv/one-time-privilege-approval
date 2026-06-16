#!/usr/bin/env python3
import argparse
import json
import os
import shlex
import subprocess
import sys
import time

from common import (
    APPROVED,
    RUNNING,
    DONE,
    REJECTED,
    LOG_DIR,
    SECURE_PATH,
    approval_hash,
    atomic_write_json,
    verify_run_password,
    acquire_lock,
    release_lock,
)

def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)

def current_user():
    return os.environ.get("SUDO_USER") or "root"

def move_to_rejected(path, manifest, reason):
    rid = manifest["approval"]["request_id"]
    manifest["state"]["status"] = "rejected"
    manifest["state"]["reason"] = reason
    manifest["state"]["rejected_at_epoch"] = int(time.time())

    atomic_write_json(path, manifest)

    target = REJECTED / f"{rid}.{reason}.json"
    if target.exists():
        target = REJECTED / f"{rid}.{reason}.{int(time.time())}.json"

    os.replace(path, target)

def make_sudo_like_env(manifest, argv):
    approval = manifest["approval"]
    requester = approval["requester"]

    return {
        "PATH": SECURE_PATH,
        "LANG": "C.UTF-8",
        "HOME": "/root",
        "USER": "root",
        "LOGNAME": "root",
        "SUDO_USER": requester,
        "SUDO_UID": str(approval["requester_uid"]),
        "SUDO_GID": str(approval["requester_gid"]),
        "SUDO_COMMAND": " ".join(shlex.quote(x) for x in argv),
    }

def run_command(manifest, cmd, log):
    argv = cmd["argv"]
    cwd = cmd.get("cwd") or manifest["approval"].get("request_cwd") or "/"
    timeout = int(cmd.get("timeout_sec", 3600))
    env = make_sudo_like_env(manifest, argv)

    printable = " ".join(shlex.quote(x) for x in argv)

    log.write(f"\nCOMMAND: {printable}\n")
    log.write(f"CWD: {cwd}\n")
    log.flush()

    print(f"+ {printable}", flush=True)

    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.write(f"TIMEOUT after {timeout} seconds\n")
        print(f"TIMEOUT after {timeout} seconds", file=sys.stderr)
        return 124

    if result.stdout:
        print(result.stdout, end="")
        log.write(result.stdout)

    log.write(f"\nEXIT: {result.returncode}\n")
    log.flush()

    return result.returncode

def main():
    parser = argparse.ArgumentParser(prog="run-approved")
    parser.add_argument("request_id")
    parser.add_argument("sha256")
    parser.add_argument("run_password")
    args = parser.parse_args()

    rid = args.request_id
    claimed_digest = args.sha256.lower()
    supplied_run_password = args.run_password

    lock = None

    try:
        lock = acquire_lock(rid)

        approved_path = APPROVED / f"{rid}.json"
        if not approved_path.exists():
            die("no approved request with that request_id")

        manifest = json.loads(approved_path.read_text(encoding="utf-8"))
        approval = manifest["approval"]
        state = manifest["state"]

        requester = approval["requester"]
        invoker = current_user()

        if invoker != requester and invoker != "root":
            die(f"this request belongs to {requester}, not {invoker}")

        actual_digest = approval_hash(manifest)
        if claimed_digest != actual_digest:
            die("SHA256 digest does not match this approved request")

        now = int(time.time())
        run_expires_at = int(state.get("run_password_expires_at_epoch", 0))

        if not run_expires_at or now > run_expires_at:
            move_to_rejected(approved_path, manifest, "expired-after-approval")
            die("approved request expired before execution")

        salt = state.get("run_password_salt", "")
        expected_hash = state.get("run_password_hash", "")

        if not salt or not expected_hash:
            move_to_rejected(approved_path, manifest, "missing-run-password-hash")
            die("approved request is missing run-password metadata")

        if not verify_run_password(supplied_run_password, salt, expected_hash):
            state["failed_run_password_attempts"] = int(state.get("failed_run_password_attempts", 0)) + 1
            max_attempts = int(state.get("max_run_password_attempts", 5))

            if state["failed_run_password_attempts"] >= max_attempts:
                move_to_rejected(approved_path, manifest, "too-many-bad-run-password")
                die("bad run password; request rejected after too many failed attempts")

            atomic_write_json(approved_path, manifest)
            die(f"bad run password; failed attempts={state['failed_run_password_attempts']}/{max_attempts}")

        # Consume before execution to prevent replay.
        running_path = RUNNING / f"{rid}.json"
        state["status"] = "running"
        state["started_at_epoch"] = int(time.time())

        # Remove password verifier before storing the running/done record.
        state.pop("run_password_salt", None)
        state.pop("run_password_hash", None)

        atomic_write_json(approved_path, manifest)
        os.replace(approved_path, running_path)

        log_path = LOG_DIR / f"{rid}.log"
        success = True
        exit_code = 0

        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"REQUEST_ID: {rid}\n")
            log.write(f"SHA256: {actual_digest}\n")
            log.write(f"REQUESTER: {requester}\n")
            log.write(f"START: {time.ctime()}\n")

            for cmd in approval["commands"]:
                rc = run_command(manifest, cmd, log)
                if rc != 0:
                    success = False
                    exit_code = rc
                    break

            log.write(f"\nEND: {time.ctime()}\n")
            log.write(f"SUCCESS: {success}\n")

        done_path = DONE / f"{rid}.json"
        state["status"] = "done"
        state["success"] = success
        state["exit_code"] = exit_code
        state["finished_at_epoch"] = int(time.time())

        atomic_write_json(running_path, manifest)
        os.replace(running_path, done_path)

        sys.exit(exit_code)

    finally:
        if lock is not None:
            release_lock(lock)

if __name__ == "__main__":
    main()