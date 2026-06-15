#!/usr/bin/env python3
import json
import time

from common import DONE, REJECTED, RUNNING, LOCKS, LOG_DIR, global_env, cfg_int

def older_than(path, days):
    age_sec = time.time() - path.stat().st_mtime
    return age_sec > days * 86400

def retention_for_manifest(path, default_days):
    try:
        m = json.loads(path.read_text(encoding="utf-8"))
        return int(m["approval"].get("retention_days", default_days))
    except Exception:
        return default_days

def main():
    g = global_env()
    default_days = cfg_int(g, "DEFAULT_RETENTION_DAYS", 30)

    for directory in [DONE, REJECTED]:
        for path in directory.glob("*.json"):
            days = retention_for_manifest(path, default_days)
            if older_than(path, days):
                rid = path.stem.split(".")[0]
                log_path = LOG_DIR / f"{rid}.log"
                if log_path.exists():
                    log_path.unlink()
                path.unlink()

    for path in RUNNING.glob("*.json"):
        if older_than(path, 7):
            path.rename(REJECTED / f"{path.stem}.stale-running.json")

    for lock in LOCKS.glob("*.lock"):
        try:
            if older_than(lock, 1):
                lock.rmdir()
        except OSError:
            pass

if __name__ == "__main__":
    main()