"""
Detector module for KeyGuard.
"""
import psutil
import os
import re
from config import Config

SUSPICIOUS_KEYWORDS = ["hook", "keylog", "spy", "monitor", "capture", "record", "input", "intercept", "stealth", "hide", "inject"]
SUSPICIOUS_MODULES = ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "keyboard", "pynput", "pyxhook", "xinput"]

class KeyloggerDetector:
    def __init__(self, config):
        self.config = config

    def evaluate(self, proc):
        score = 0.0
        reasons = []
        try:
            name = (proc.name() or "").lower()
            cmdline = " ".join(proc.cmdline()).lower()
            exe = (proc.exe() or "").lower()
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in name or kw in cmdline:
                    score += 1.5
                    reasons.append(f"Suspicious keyword '{kw}' in process name/cmdline")
                    break
            try:
                for f in proc.open_files():
                    if f.path.endswith(('.txt', '.log', '.dat')) and f.mode in ('a', 'w', 'r+'):
                        score += 1.5
                        reasons.append(f"Writing to log-like file: {f.path}")
                        break
            except: pass
            suspicious_dirs = ['temp', 'tmp', '/tmp']
            if any(d in exe for d in suspicious_dirs):
                score += 1.5
                reasons.append(f"Executable running from suspicious path: {exe}")
            for mod in SUSPICIOUS_MODULES:
                if mod.lower() in cmdline:
                    score += 2.0
                    reasons.append(f"Suspicious module reference: {mod}")
                    break
        except: pass
        return min(round(score, 1), 10.0), reasons

    def evaluate_file(self, filepath):
        name = os.path.basename(filepath).lower()
        return min(sum(1.0 for kw in SUSPICIOUS_KEYWORDS if kw in name) * 2, 10.0)

    def evaluate_file_content(self, content):
        import re
        patterns = [r"SetWindowsHookEx", r"GetAsyncKeyState", r"pynput\.keyboard", r"keyboard\.on_press"]
        score = sum(2.0 for p in patterns if re.search(p, content))
        return min(score, 10.0)
