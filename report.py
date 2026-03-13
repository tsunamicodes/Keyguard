"""
report.py — Generate a summary report from KeyGuard log data.
Usage: python report.py [log_file]
"""

import sys
import json
from collections import Counter
from logger import ActivityLogger


def generate_report(log_file: str = "logs/keyguard.log"):
    entries = ActivityLogger.read_log(log_file)
    if not entries:
        print("No log data found.")
        return

    total_scans = len(entries)
    alert_scans = [e for e in entries if e.get("suspicious_processes")]
    all_procs = [p for e in alert_scans for p in e["suspicious_processes"]]
    name_counter = Counter(p["name"] for p in all_procs)

    print("=" * 50)
    print("         KEYGUARD SECURITY REPORT")
    print("=" * 50)
    print(f"Total scans run    : {total_scans}")
    print(f"Scans with alerts  : {len(alert_scans)}")
    print(f"Alert rate         : {len(alert_scans)/total_scans*100:.1f}%")
    print()

    if name_counter:
        print("Top flagged processes:")
        for name, count in name_counter.most_common(5):
            print(f"  {name:<30} flagged {count}x")
    else:
        print("No suspicious processes detected across all scans. ✓")

    print()
    print("Startup persistence checks:")
    startup_hits = [e for e in entries if e.get("suspicious_startup_entries")]
    print(f"  Suspicious entries found in {len(startup_hits)} scan(s)")
    print("=" * 50)


if __name__ == "__main__":
    log_file = sys.argv[1] if len(sys.argv) > 1 else "logs/keyguard.log"
    generate_report(log_file)
