"""
KeyGuard - System Activity Monitor & Keylogger Behavior Detector
Monitors running processes and system calls for suspicious keylogging behavior.
"""

import psutil
import time
import json
import os
import hashlib
from datetime import datetime
from detector import KeyloggerDetector
from logger import ActivityLogger
from config import Config


class KeyGuard:
    def __init__(self, config: Config):
        self.config = config
        self.detector = KeyloggerDetector(config)
        self.logger = ActivityLogger(config.log_file)
        self.known_processes = {}
        self.alert_count = 0

    def scan_processes(self):
        """Scan all running processes for suspicious behavior."""
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'connections', 'open_files']):
            try:
                info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'status'])
                score, reasons = self.detector.evaluate(proc)
                if score >= self.config.alert_threshold:
                    suspicious.append({
                        "pid": info['pid'],
                        "name": info['name'],
                        "exe": info.get('exe', 'unknown'),
                        "risk_score": score,
                        "reasons": reasons,
                        "timestamp": datetime.now().isoformat()
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return suspicious

    def check_startup_persistence(self):
        """Check common persistence locations used by keyloggers."""
        suspicious_paths = []
        startup_dirs = [
            os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            "/etc/init.d",
            "/etc/rc.local",
            os.path.expanduser("~/.bashrc"),
            os.path.expanduser("~/.profile"),
        ]
        for path in startup_dirs:
            if os.path.exists(path):
                if os.path.isdir(path):
                    for f in os.listdir(path):
                        fp = os.path.join(path, f)
                        score = self.detector.evaluate_file(fp)
                        if score > 0:
                            suspicious_paths.append({"path": fp, "risk_score": score})
                else:
                    with open(path, 'r', errors='ignore') as f:
                        content = f.read()
                        score = self.detector.evaluate_file_content(content)
                        if score > 0:
                            suspicious_paths.append({"path": path, "risk_score": score})
        return suspicious_paths

    def monitor(self):
        """Main monitoring loop."""
        print(f"[KeyGuard] Starting monitor — scan interval: {self.config.scan_interval}s")
        print(f"[KeyGuard] Alert threshold: {self.config.alert_threshold}/10\n")

        while True:
            try:
                result = {
                    "scan_time": datetime.now().isoformat(),
                    "suspicious_processes": self.scan_processes(),
                    "suspicious_startup_entries": self.check_startup_persistence(),
                }

                # Log always
                self.logger.log(result)

                # Print alerts
                if result["suspicious_processes"]:
                    self.alert_count += 1
                    print(f"\n⚠️  ALERT #{self.alert_count} — {result['scan_time']}")
                    for proc in result["suspicious_processes"]:
                        print(f"  PID {proc['pid']} | {proc['name']} | Score: {proc['risk_score']}/10")
                        for reason in proc['reasons']:
                            print(f"    → {reason}")
                else:
                    print(f"[{result['scan_time']}] ✓ Clean scan")

                time.sleep(self.config.scan_interval)

            except KeyboardInterrupt:
                print("\n[KeyGuard] Monitoring stopped.")
                self.logger.close()
                break


if __name__ == "__main__":
    config = Config()
    guard = KeyGuard(config)
    guard.monitor()
