"""
KeyGuard
"""
import psutil
import time
from datetime import datetime
from detector import KeyloggerDetector
from logger import ActivityLogger
from config import Config

class KeyGuard:
    def __init__(self, config):
        self.config = config
        self.detector = KeyloggerDetector(config)
        self.logger = ActivityLogger(config.log_file)
        self.alert_count = 0

    def scan_processes(self):
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'status'])
                score, reasons = self.detector.evaluate(proc)
                if score >= self.config.alert_threshold:
                    suspicious.append({"pid": info['pid'], "name": info['name'], "risk_score": score, "reasons": reasons, "timestamp": datetime.now().isoformat()})
            except: continue
        return suspicious

    def monitor(self):
        print(f"[KeyGuard] Starting monitor")
        while True:
            try:
                result = {"scan_time": datetime.now().isoformat(), "suspicious_processes": self.scan_processes()}
                self.logger.log(result)
                if result["suspicious_processes"]:
                    self.alert_count += 1
                time.sleep(self.config.scan_interval)
            except KeyboardInterrupt:
                self.logger.close(); break

if __name__ == "__main__":
    config = Config()
    guard = KeyGuard(config)
    guard.monitor()
