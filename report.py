"""
report.py - Generate a summary report from KeyGuard log data.
"""

import sys
from collections import Counter
from logger import ActivityLogger


def generate_report(log_file="logs/keyguard.log"):
    entries = ActivityLogger.read_log(log_file)
    if not entries:
        print("No log data found.")
        return
    total = len(entries)
    alerts = [e for e in entries if e.get("suspicious_processes")]
    print(f"Total scans: {total} | Alerts: {len(alerts)} | Alert rate: {len(alerts)/total*100:.1f}%")

if __name__ == "__main__":
    log = sys.argv[1] if len(sys.argv) > 1 else "logs/keyguard.log"
    generate_report(log)
