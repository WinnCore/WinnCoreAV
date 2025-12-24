#!/usr/bin/env python3
"""Collect lightweight compliance evidence for audits."""

import argparse
import json
import os
from pathlib import Path


def parse_login_defs():
    path = Path("/etc/login.defs")
    if not path.exists():
        return {}
    data = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            data[parts[0]] = parts[1]
    return data


def read_users():
    users = []
    try:
        for line in Path("/etc/passwd").read_text().splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                users.append({
                    "name": parts[0],
                    "uid": int(parts[2]),
                    "gid": int(parts[3]),
                    "shell": parts[6],
                })
    except Exception:
        return []
    return users


def main():
    parser = argparse.ArgumentParser(description="Collect compliance evidence")
    parser.add_argument(
        "--output",
        default="test-results/compliance_report.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    users = read_users()
    privileged = [u for u in users if u.get("uid") == 0]
    login_defs = parse_login_defs()

    report = {
        "report_metadata": {
            "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "framework": os.environ.get("WINNCORE_COMPLIANCE_FRAMEWORK", "SOC2"),
            "product": "WinnCoreAV EDR",
        },
        "access_control": {
            "user_accounts": users,
            "privileged_accounts": privileged,
            "password_policy": {
                "PASS_MAX_DAYS": login_defs.get("PASS_MAX_DAYS"),
                "PASS_MIN_DAYS": login_defs.get("PASS_MIN_DAYS"),
                "PASS_MIN_LEN": login_defs.get("PASS_MIN_LEN"),
                "PASS_WARN_AGE": login_defs.get("PASS_WARN_AGE"),
            },
        },
        "audit_logging": {
            "winncore_logs_present": Path("/var/log/winncore").exists(),
            "alert_log": os.environ.get("WINNCORE_ALERT_LOG", "/var/log/winncore/alerts.json"),
        },
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    print(f"Compliance report written to {out_path}")


if __name__ == "__main__":
    raise SystemExit(main())
