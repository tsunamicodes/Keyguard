import sys
from collections import Counter
from logger import ActivityLogger

def generate_report(log_file="logs/keyguard.log"):
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
    print(f"Total scans: {total_scans} | Alerts: {len(alert_scans)}")
    if name_counter:
        for name, count in name_counter.most_common(5):
            print(f"  {name:<30} {count}x")

if __name__ == "__main__":
    log_file = sys.argv[1] if len(sys.argv) > 1 else "logs/keyguard.log"
    generate_report(log_file)
